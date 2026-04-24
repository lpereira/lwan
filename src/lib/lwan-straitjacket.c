/*
 * lwan - web server
 * Copyright (c) 2015 L. A. F. Pereira <l@tia.mat.br>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwan-private.h"

#include "lwan-config.h"
#include "lwan-status.h"

static bool get_user_uid_gid(const char *user, uid_t *uid, gid_t *gid)
{
    struct passwd pwd = {};
    struct passwd *result;
    char *buf;
    long pw_size_max = sysconf(_SC_GETPW_R_SIZE_MAX);
    int r;

    if (pw_size_max < 0) {
        /* This constant is returned for sysconf(_SC_GETPW_R_SIZE_MAX) in glibc,
         * and it seems to be a reasonable size (1024).  Use it as a fallback in
         * the (very unlikely) case where sysconf() fails. */
        pw_size_max = NSS_BUFLEN_PASSWD;
    }

    buf = malloc((size_t)pw_size_max);
    if (!buf) {
        lwan_status_error("Could not allocate buffer for passwd struct");
        return false;
    }

    r = getpwnam_r(user, &pwd, buf, (size_t)pw_size_max, &result);
    *uid = pwd.pw_uid;
    *gid = pwd.pw_gid;
    free(buf);

    if (result)
        return true;

    if (!r) {
        lwan_status_error("Username not found: %s", user);
    } else {
        errno = r;
        lwan_status_perror("Could not obtain uid/gid for user %s", user);
    }

    return false;
}

static bool switch_to_user(uid_t uid, gid_t gid, const char *username)
{
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;

    lwan_status_info("Dropping privileges to UID %d, GID %d (%s)", uid, gid,
                     username);

    if (setresgid(gid, gid, gid) < 0)
        return false;
#if defined(__APPLE__)
    if (initgroups(username, (int)gid) < 0)
        return false;
#else
    if (initgroups(username, gid) < 0)
        return false;
#endif
    if (setresuid(uid, uid, uid) < 0)
        return false;

    if (getresuid(&ruid, &euid, &suid) < 0)
        return false;
    if (ruid != euid || euid != suid || suid != uid)
        return false;

    if (getresgid(&rgid, &egid, &sgid) < 0)
        return false;
    if (rgid != egid || egid != sgid || sgid != gid)
        return false;

    return true;
}

#ifdef LWAN_HAVE_LANDLOCK
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <fcntl.h>

struct lwan_landlock {
    struct landlock_ruleset_attr attr;
    uint32_t restrict_flags;
    int ruleset_fd;
};

static inline int
lwan_landlock_create_ruleset(const struct landlock_ruleset_attr *attr,
                             const size_t size,
                             uint32_t flags)
{
    return (int)syscall(SYS_landlock_create_ruleset, attr, size, flags);
}

static inline int lwan_landlock_add_rule(int fd,
                                         enum landlock_rule_type type,
                                         const void *rule_attr,
                                         uint32_t flags)
{
    return (int)syscall(SYS_landlock_add_rule, fd, type, rule_attr, flags);
}

static inline int lwan_landlock_restrict_self(int fd, uint32_t flags)
{
    return (int)syscall(SYS_landlock_restrict_self, fd, flags);
}

LWAN_LAZY_GLOBAL(struct lwan_landlock *, get_landlock_ruleset)
{
    struct lwan_landlock *ll;

    ll = malloc(sizeof(*ll));
    if (!ll)
        return NULL;

    ll->attr = (struct landlock_ruleset_attr){
        .handled_access_fs =
            LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
            LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
            LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
            LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
            LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
            LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER |
            LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_IOCTL_DEV,
        .handled_access_net =
            LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
        .scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL,
    };

    int abi =
        lwan_landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi <= 0) {
        /* From landlock_create_ruleset(2): "If attr is NULL and size is 0,
         * then the returned value is the highest supported Landlock ABI
         * version (starting at 1)." */
        switch (errno) {
        case EOPNOTSUPP:
            lwan_status_error("Landlock disabled on this kernel");
            break;
        case ENOSYS:
            lwan_status_error("Landlock not present in this kernel");
            break;
        default:
            lwan_status_perror("Unknown error determining Landlock ABI version");
        }
        goto err;
    }

    ll->restrict_flags = 0;
#if defined(LANDLOCK_RESTRICT_SELF_TSYNC)
    if (abi >= 7)
        ll->restrict_flags = LANDLOCK_RESTRICT_SELF_TSYNC;
#endif

    /* From the Linux kernel doc: "To be compatible with older Linux
     * versions, we detect the available Landlock ABI version, and only use
     * the available subset of access rights" */
    switch (abi) {
    case 1:
        /* Removes LANDLOCK_ACCESS_FS_REFER for ABI < 2 */
        ll->attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
        /* fallthrough */
    case 2:
        /* Removes LANDLOCK_ACCESS_FS_TRUNCATE for ABI < 3 */
        ll->attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
        /* fallthrough */
    case 3:
        /* Removes network support for ABI < 4 */
        ll->attr.handled_access_net &=
            ~(LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP);
        /* fallthrough */
    case 4:
        /* Removes LANDLOCK_ACCESS_FS_IOCTL_DEV for ABI < 5 */
        ll->attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
        /* fallthrough */
    case 5:
        /* Removes LANDLOCK_SCOPE_* for ABI < 6 */
        ll->attr.scoped &=
            ~(LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL);
    }

    int ruleset_fd =
        lwan_landlock_create_ruleset(&ll->attr, sizeof(ll->attr), 0);
    if (ruleset_fd < 0) {
        lwan_status_perror("Failed to create a Landlock ruleset");
        goto err;
    }

    ll->ruleset_fd = ruleset_fd;

    return ll;

err:
    free(ll);
    return NULL;
}

static inline struct lwan_landlock *get_landlock(void)
{
    struct lwan_landlock *ll = get_landlock_ruleset();

    if (!ll) {
        lwan_status_debug("Could not get Landlock ruleset");
        return NULL;
    }

    if (ll->ruleset_fd < 0) {
        lwan_status_debug("Landlock already in enforcing mode");
        return NULL;
    }

    return ll;
}

static bool lwan_straitjacket_allow_path(uint64_t allowed_access, int fd)
{
    struct lwan_landlock *ll = get_landlock();

    if (!ll)
        return false;

    if ((ll->attr.handled_access_fs & allowed_access) != allowed_access)
        return false;

    struct landlock_path_beneath_attr path_beneath = {
        .parent_fd = fd,
        .allowed_access = allowed_access,
    };

    return lwan_landlock_add_rule(ll->ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                  &path_beneath, 0) == 0;
}

bool lwan_straitjacket_allow_dirfd_ro(int fd)
{
    return lwan_straitjacket_allow_path(
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR, fd);
}

bool lwan_straitjacket_allow_dirfd_rw(int fd)
{
    return lwan_straitjacket_allow_path(
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
        LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG, fd);
}

static bool lwan_straitjacket_allow_net(uint64_t allowed_access, int port)
{
    struct lwan_landlock *ll = get_landlock();

    if (!ll)
        return false;

    if ((ll->attr.handled_access_net & allowed_access) != allowed_access) {
        lwan_status_debug("Kernel doesn't support requested access");
        return false;
    }

    struct landlock_net_port_attr net_port = {
        .allowed_access = allowed_access,
        .port = (__u64)port,
    };

    return lwan_landlock_add_rule(ll->ruleset_fd, LANDLOCK_RULE_NET_PORT,
                                  &net_port, 0) == 0;
}

bool lwan_straitjacket_allow_bind(int port)
{
    return lwan_straitjacket_allow_net(LANDLOCK_ACCESS_NET_BIND_TCP, port);
}

bool lwan_straitjacket_allow_connect(int port)
{
    return lwan_straitjacket_allow_net(LANDLOCK_ACCESS_NET_CONNECT_TCP, port);
}

bool lwan_straitjacket_allow_dir_path_ro(const char *path)
{
    int fd = open(path, O_CLOEXEC | O_DIRECTORY);
    if (fd < 0)
        return false;
    bool allow = lwan_straitjacket_allow_dirfd_ro(fd);
    close(fd);
    return allow;
}

bool lwan_straitjacket_allow_dir_path_rw(const char *path)
{
    int fd = open(path, O_CLOEXEC | O_DIRECTORY);
    if (fd < 0)
        return false;
    bool allow = lwan_straitjacket_allow_dirfd_rw(fd);
    close(fd);
    return allow;
}

static void add_base_rules(void)
{
    /* FIXME: this is too broad, but it's kinda hard to know
     * which files libc will open; on my system, only /etc/localtime
     * is needed, but others might be necessary. */
    lwan_straitjacket_allow_dir_path_ro("/etc");

#if defined(__linux__)
    /* Required to query somaxconn and tcp_allowed_congestion_control */
    lwan_straitjacket_allow_dir_path_ro("/proc/sys/net");

    /* Required for proc_pidpath if getauxval(AT_EXECFN) fails */
    lwan_straitjacket_allow_dir_path_ro("/proc/self");
#endif

#if defined(__x86_64__)
    /* Required to read the CPU topology */
    lwan_straitjacket_allow_dir_path_ro("/sys/devices/system/cpu");
#endif
}

bool lwan_landlock_enforce(void)
{
    struct lwan_landlock *ll = get_landlock();

    if (!ll)
        return false;

    add_base_rules();

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        lwan_status_perror("Failed to restrict privileges");
        return false;
    }

    if (lwan_landlock_restrict_self(ll->ruleset_fd, ll->restrict_flags)) {
        lwan_status_perror("Couldn't enable Landlock ruleset");
        return false;
    }

    close(ll->ruleset_fd);
    lwan_always_bzero(ll, sizeof(*ll));
    ll->ruleset_fd = -1;

    lwan_status_debug("Landlock in enforcement mode");
    return true;
}

static inline bool lwan_landlock_available(void) {
    return !!get_landlock();
}
#else
static inline bool lwan_landlock_available(void) { return false; }
bool lwan_landlock_enforce(void) { return false; }

bool lwan_straitjacket_allow_bind(int port) { return false; }
bool lwan_straitjacket_allow_connect(int port) { return false; }
bool lwan_straitjacket_allow_dirfd_ro(int fd) { return false; }
bool lwan_straitjacket_allow_dirfd_rw(int fd) { return false; }
bool lwan_straitjacket_allow_dir_path_ro(const char *path) { return false; }
bool lwan_straitjacket_allow_dir_path_rw(const char *path) { return false; }
#endif /* LWAN_HAVE_LANDLOCK */

#ifdef __linux__
static void abort_on_open_directories(void)
{
    /* This is racy, but is a way to detect misconfiguration.  Since it's
     * called just once during boot time, before threads are created, this
     * should be fine (maybe not if Lwan is used as a library.)
     */
    DIR *dir = opendir("/proc/self/fd");
    struct dirent *ent;
    char own_fd[3 * sizeof(int)];
    int ret;

    if (!dir) {
        lwan_status_critical_perror(
            "Could not determine if there are open directory fds");
    }

    ret = snprintf(own_fd, sizeof(own_fd), "%d", dirfd(dir));
    if (ret < 0 || ret >= (int)sizeof(own_fd)) {
        lwan_status_critical("Could not get descriptor of /proc/self/fd");
    }

    while ((ent = readdir(dir))) {
        char path[PATH_MAX];
        struct stat st;
        ssize_t len;

        if (streq(ent->d_name, own_fd))
            continue;
        if (streq(ent->d_name, ".") || streq(ent->d_name, ".."))
            continue;

        len = readlinkat(dirfd(dir), ent->d_name, path, sizeof(path));
        if (len < 0) {
            lwan_status_critical_perror("Could not get information about fd %s",
                                        ent->d_name);
        }
        path[len] = '\0';

        if (path[0] != '/') {
            /* readlink() there will point to the realpath() of a file, so
             * if it's on a filesystem, it starts with '/'.  Sockets, for
             * instance, begin with "socket:" instead...  so no need for
             * stat().  */
            continue;
        }

        if (stat(path, &st) < 0) {
            lwan_status_critical_perror(
                "Could not get information about open file: %s", path);
        }

        if (S_ISDIR(st.st_mode)) {
            closedir(dir);

            lwan_status_critical(
                "The directory '%s' is open (fd %s), can't chroot", path,
                ent->d_name);
            return;
        }
    }

    closedir(dir);
}
#else
static void abort_on_open_directories(void) {}
#endif

static void enforce_user(const struct lwan_straitjacket *sj)
{
    uid_t uid = 0;
    gid_t gid = 0;
    bool got_uid_gid = false;

    if (!sj->user_name)
        return;

    if (sj->user_name && *sj->user_name) {
        if (!get_user_uid_gid(sj->user_name, &uid, &gid))
            lwan_status_critical("Unknown user: %s", sj->user_name);
        got_uid_gid = true;
    }

    if (got_uid_gid && !switch_to_user(uid, gid, sj->user_name)) {
        lwan_status_critical("Could not drop privileges to %s, aborting",
                             sj->user_name);
    }
}

static void enforce_chroot(const struct lwan_straitjacket *sj)
{
    if (!sj->chroot_path)
        return;

    if (geteuid() != 0)
        lwan_status_critical("Straitjacket with chroot(2) requires root privileges");

    abort_on_open_directories();

    if (chroot(sj->chroot_path) < 0) {
        lwan_status_critical_perror("Could not chroot() to %s",
                                    sj->chroot_path);
    }

    if (chdir("/") < 0)
        lwan_status_critical_perror("Could not chdir() to /");

    lwan_status_info("Jailed to %s", sj->chroot_path);
}

void lwan_straitjacket_enforce(const struct lwan_straitjacket *sj)
{
    enforce_user(sj);

    if (!lwan_landlock_available())
        enforce_chroot(sj);

    if (sj->drop_capabilities) {
        struct __user_cap_header_struct header = {
            .version = _LINUX_CAPABILITY_VERSION_1,
        };
        struct __user_cap_data_struct data = {};

        if (capset(&header, &data) < 0)
            lwan_status_critical_perror("Could not drop capabilities");
    }
}

void lwan_straitjacket_enforce_from_config(struct config *c)
{
    const struct config_line *l;
    char *user_name = NULL;
    char *chroot_path = NULL;
    bool drop_capabilities = true;

    while ((l = config_read_line(c))) {
        switch (l->type) {
        case CONFIG_LINE_TYPE_LINE:
            /* TODO: limit_syscalls */
            if (streq(l->key, "user")) {
                if (user_name) {
                    config_error(c, "`user' already specified");
                    return;
                }
                user_name = strdupa(l->value);
            } else if (streq(l->key, "chroot")) {
                if (chroot_path) {
                    config_error(c, "`chroot' already specified");
                    return;
                }
                if (lwan_landlock_available()) {
                    config_error(c, "`chroot' doesn't work on builds with Landlock support");
                    return;
                }
                chroot_path = strdupa(l->value);
            } else if (streq(l->key, "drop_capabilities")) {
                drop_capabilities = parse_bool(l->value, true);
            } else {
                config_error(c, "Invalid key: %s", l->key);
                return;
            }
            break;
        case CONFIG_LINE_TYPE_SECTION:
            config_error(c, "Straitjacket accepts no sections");
            return;
        case CONFIG_LINE_TYPE_SECTION_END:
            lwan_straitjacket_enforce(&(struct lwan_straitjacket){
                .user_name = user_name,
                .chroot_path = chroot_path,
                .drop_capabilities = drop_capabilities,
            });

            return;
        }
    }

    config_error(c, "Expecting section end while parsing straitjacket");
}

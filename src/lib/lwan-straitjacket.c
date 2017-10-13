/*
 * lwan - simple web server
 * Copyright (c) 2015 Leandro A. F. Pereira <leandro@hardinfo.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "lwan-private.h"

#include "lwan-config.h"
#include "lwan-status.h"

static bool get_user_uid_gid(const char *user, uid_t *uid, gid_t *gid)
{
    struct passwd pwd = { };
    struct passwd *result;
    char *buf;
    long pw_size_max = sysconf(_SC_GETPW_R_SIZE_MAX);
    int r;

    if (pw_size_max < 0)
        pw_size_max = 16384;

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

    lwan_status_info("Dropping privileges to UID %d, GID %d (%s)",
        uid, gid, username);

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

        if (!strcmp(ent->d_name, own_fd))
            continue;
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
            continue;

        len = readlinkat(dirfd(dir), ent->d_name, path, sizeof(path));
        if (len < 0) {
            lwan_status_critical_perror(
                "Could not get information about fd %s", ent->d_name);
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
                "The directory '%s' is open (fd %s), can't chroot",
                path, ent->d_name);
            return;
        }
    }

    closedir(dir);
}
#else
static void abort_on_open_directories(void)
{
}
#endif

void lwan_straitjacket_enforce(const struct lwan_straitjacket *sj)
{
    uid_t uid;
    gid_t gid;

    if (!sj->user_name && !sj->chroot_path)
        return;

    if (geteuid() != 0) {
        lwan_status_critical("Straitjacket requires root privileges");
        return;
    }

    if (sj->user_name && *sj->user_name) {
        if (!get_user_uid_gid(sj->user_name, &uid, &gid)) {
            lwan_status_critical("Unknown user: %s", sj->user_name);
            return;
        }
    }

    if (sj->chroot_path) {
        abort_on_open_directories();

        if (chroot(sj->chroot_path) < 0) {
            lwan_status_critical_perror("Could not chroot() to %s",
                sj->chroot_path);
        }

        if (chdir("/") < 0)
            lwan_status_critical_perror("Could not chdir() to /");

        lwan_status_info("Jailed to %s", sj->chroot_path);
    }

    if (sj->user_name && *sj->user_name) {
        if (!switch_to_user(uid, gid, sj->user_name)) {
            lwan_status_critical("Could not drop privileges to %s, aborting",
                sj->user_name);
        }
    }
}

void lwan_straitjacket_enforce_from_config(struct config *c)
{
    struct config_line l;
    char *user_name = NULL;
    char *chroot_path = NULL;

    while (config_read_line(c, &l)) {
        switch (l.type) {
        case CONFIG_LINE_TYPE_LINE:
            /* TODO: limit_syscalls */
            if (streq(l.key, "user")) {
                user_name = strdupa(l.value);
            } else if (streq(l.key, "chroot")) {
                chroot_path = strdupa(l.value);
            } else {
                config_error(c, "Invalid key: %s", l.key);
                return;
            }
            break;
        case CONFIG_LINE_TYPE_SECTION:
            config_error(c, "Straitjacket accepts no sections");
            return;
        case CONFIG_LINE_TYPE_SECTION_END:
            lwan_straitjacket_enforce(&(struct lwan_straitjacket) {
                .user_name = user_name,
                .chroot_path = chroot_path,
            });

            return;
        }
    }

    config_error(c, "Expecting section end while parsing straitjacket");
}

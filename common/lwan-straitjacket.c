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
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwan-config.h"
#include "lwan-status.h"

static bool get_user_uid_gid(const char *user, uid_t *uid, gid_t *gid)
{
    struct passwd pwd = { };
    struct passwd *result;
    char *buf;
    long pw_size_max = sysconf(_SC_GETPW_R_SIZE_MAX);
    int r;

    if (!user || !*user) {
        lwan_status_error("Username should be provided");
        return false;
    }

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
    lwan_status_info("Dropping privileges to UID %d, GID %d (%s)",
        uid, gid, username);

    if (setgid(gid) < 0)
        return false;
    if (setuid(uid) < 0)
        return false;

    return getegid() == gid && geteuid() == uid;
}

void lwan_straitjacket_enforce(config_t *c, config_line_t *l)
{
    char *user_name = NULL;
    char *chroot_path = NULL;
    uid_t uid;
    gid_t gid;

    if (geteuid() != 0) {
        config_error(c, "Straitjacket requires root privileges");
        return;
    }

    while (config_read_line(c, l)) {
        switch (l->type) {
        case CONFIG_LINE_TYPE_LINE:
            /* TODO: limit_syscalls */
            if (!strcmp(l->line.key, "user")) {
                user_name = strdupa(l->line.value);
            } else if (!strcmp(l->line.key, "chroot")) {
                chroot_path = strdupa(l->line.value);
            } else {
                config_error(c, "Invalid key: %s", l->line.key);
                return;
            }
            break;
        case CONFIG_LINE_TYPE_SECTION:
            config_error(c, "Straitjacket accepts no sections");
            return;
        case CONFIG_LINE_TYPE_SECTION_END:
            if (!get_user_uid_gid(user_name, &uid, &gid)) {
                config_error(c, "Unknown user: %s", user_name);
                return;
            }

            if (chroot_path) {
                if (chroot(chroot_path) < 0) {
                    lwan_status_critical_perror("Could not chroot() to %s",
                        chroot_path);
                }
                lwan_status_debug("Jailed to %s", chroot_path);
            }

            if (!switch_to_user(uid, gid, user_name)) {
                lwan_status_critical("Could not drop privileges to %s, aborting",
                    user_name);
            }
            return;
        }
    }

    config_error(c, "Expecting section end while parsing straitjacket");
}

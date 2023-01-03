/*
 * lwan - web server
 * Copyright (c) 2012 L. A. F. Pereira <l@tia.mat.br>
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

#include_next <string.h>

#ifndef MISSING_STRING_H
#define MISSING_STRING_H

#include <stdbool.h>

#define strndupa_impl(s, l)                                                    \
    ({                                                                         \
        char *strndupa_tmp_s = alloca(l + 1);                                  \
        strndupa_tmp_s[l] = '\0';                                              \
        strncpy(strndupa_tmp_s, s, l);                                          \
    })

#ifndef strndupa
#define strndupa(s, l) strndupa_impl((s), strnlen((s), (l)))
#undef NEED_ALLOCA_H
#define NEED_ALLOCA_H
#endif

#ifndef strdupa
#define strdupa(s) strndupa((s), strlen(s))
#undef NEED_ALLOCA_H
#define NEED_ALLOCA_H
#endif

#ifdef NEED_ALLOCA_H
#undef NEED_ALLOCA_H
#ifdef LWAN_HAVE_ALLOCA_H
#include <alloca.h>
#else
#include <stdlib.h>
#endif
#endif

#ifndef LWAN_HAVE_MEMPCPY
void *mempcpy(void *dest, const void *src, size_t len);
#endif

#ifndef LWAN_HAVE_MEMRCHR
void *memrchr(const void *s, int c, size_t n);
#endif

#ifndef LWAN_HAVE_STPCPY
char *stpcpy(char *restrict dst, const char *restrict src);
char *stpncpy(char *restrict dst, const char *restrict src, size sz);
#endif

static inline int streq(const char *a, const char *b)
{
    return strcmp(a, b) == 0;
}

static inline void *mempmove(void *dest, const void *src, size_t len)
{
    char *d = (char *)memmove(dest, src, len);
    return d + len;
}

bool strcaseequal_neutral(const char *a, const char *b);

#endif /* MISSING_STRING_H */

/*
 * lwan - simple web server
 * Copyright (c) 2012 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#include_next <string.h>

#ifndef MISSING_STRING_H
#define MISSING_STRING_H

#define strndupa_impl(s, l) ({ \
   char *strndupa_tmp_s = alloca(l + 1); \
   strndupa_tmp_s[l] = '\0'; \
   memcpy(strndupa_tmp_s, s, l); \
})

#ifndef strndupa
#define strndupa(s, l) strndupa_impl((s), strnlen((s), (l)))
#endif

#ifndef strdupa
#define strdupa(s) strndupa((s), strlen(s))
#endif

#ifndef HAS_RAWMEMCHR
void *rawmemchr(const void *ptr, char c);
#endif

#ifndef HAS_MEMPCPY
void *mempcpy(void *dest, const void *src, size_t len);
#endif

#ifndef HAS_MEMRCHR
void *memrchr(const void *s, int c, size_t n);
#endif

static inline int
streq(const char *a, const char *b)
{
   return strcmp(a, b) == 0;
}

static inline void *
mempmove(void *dest, const void *src, size_t len)
{
   unsigned char *d = memmove(dest, src, len);
   return d + len;
}

#endif /* MISSING_STRING_H */

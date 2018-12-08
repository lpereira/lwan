/*
 * lwan - simple web server
 * Copyright (c) 2017 Leandro A. F. Pereira <leandro@hardinfo.org>
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
#include <stdio.h>
#include <errno.h>
#include <time.h>

#include "lwan-private.h"

static int parse_2_digit_num(const char *str, const char end_chr, int min, int max)
{
    int val;

    if (UNLIKELY(!lwan_char_isdigit(*str)))
        return -EINVAL;
    if (UNLIKELY(!lwan_char_isdigit(*(str + 1))))
        return -EINVAL;
    if (UNLIKELY(*(str + 2) != end_chr))
        return -EINVAL;

    val = (*str - '0') * 10;
    val += *(str + 1) - '0';

    if (UNLIKELY(val < min || val > max))
        return -EINVAL;

    return val;
}

int lwan_parse_rfc_time(const char in[static 30], time_t *out)
{
    /* This function is used instead of strptime() because locale
     * information can affect the parsing.  Instead of defining
     * the locale to "C", use hardcoded constants. */
    struct tm tm;
    const char *str = in;

    STRING_SWITCH(str) {
    case MULTICHAR_CONSTANT('S','u','n',','): tm.tm_wday = 0; break;
    case MULTICHAR_CONSTANT('M','o','n',','): tm.tm_wday = 1; break;
    case MULTICHAR_CONSTANT('T','u','e',','): tm.tm_wday = 2; break;
    case MULTICHAR_CONSTANT('W','e','d',','): tm.tm_wday = 3; break;
    case MULTICHAR_CONSTANT('T','h','u',','): tm.tm_wday = 4; break;
    case MULTICHAR_CONSTANT('F','r','i',','): tm.tm_wday = 5; break;
    case MULTICHAR_CONSTANT('S','a','t',','): tm.tm_wday = 6; break;
    default: return -EINVAL;
    }
    str += 5;

    tm.tm_mday = parse_2_digit_num(str, ' ', 1, 31);
    if (UNLIKELY(tm.tm_mday < 0))
        return -EINVAL;
    str += 3;

    STRING_SWITCH(str) {
    case MULTICHAR_CONSTANT('J','a','n',' '): tm.tm_mon = 0; break;
    case MULTICHAR_CONSTANT('F','e','b',' '): tm.tm_mon = 1; break;
    case MULTICHAR_CONSTANT('M','a','r',' '): tm.tm_mon = 2; break;
    case MULTICHAR_CONSTANT('A','p','r',' '): tm.tm_mon = 3; break;
    case MULTICHAR_CONSTANT('M','a','y',' '): tm.tm_mon = 4; break;
    case MULTICHAR_CONSTANT('J','u','n',' '): tm.tm_mon = 5; break;
    case MULTICHAR_CONSTANT('J','u','l',' '): tm.tm_mon = 6; break;
    case MULTICHAR_CONSTANT('A','u','g',' '): tm.tm_mon = 7; break;
    case MULTICHAR_CONSTANT('S','e','p',' '): tm.tm_mon = 8; break;
    case MULTICHAR_CONSTANT('O','c','t',' '): tm.tm_mon = 9; break;
    case MULTICHAR_CONSTANT('N','o','v',' '): tm.tm_mon = 10; break;
    case MULTICHAR_CONSTANT('D','e','c',' '): tm.tm_mon = 11; break;
    default: return -EINVAL;
    }
    str += 4;

    tm.tm_year = parse_int(strndupa(str, 4), -1);
    if (UNLIKELY(tm.tm_year < 0))
        return -EINVAL;
    tm.tm_year -= 1900;
    if (UNLIKELY(tm.tm_year < 0 || tm.tm_year > 1000))
        return -EINVAL;
    str += 5;

    tm.tm_hour = parse_2_digit_num(str, ':', 0, 23);
    str += 3;
    tm.tm_min = parse_2_digit_num(str, ':', 0, 59);
    str += 3;
    tm.tm_sec = parse_2_digit_num(str, ' ', 0, 59);
    str += 3;

    STRING_SWITCH(str) {
    case MULTICHAR_CONSTANT('G','M','T','\0'):
        tm.tm_isdst = -1;

        *out = timegm(&tm);

        if (UNLIKELY(*out == (time_t)-1))
            return -EINVAL;

        return 0;

    default:
        return -EINVAL;
    }
}

int lwan_format_rfc_time(const time_t in, char out[static 30])
{
    static const char *weekdays = "SunMonTueWedThuFriSat";
    static const char *months = "JanFebMarAprMayJunJulAugSepOctNovDec";
    const char *weekday, *month;
    struct tm tm;
    int r;

    if (UNLIKELY(!gmtime_r(&in, &tm)))
        return -errno;

    weekday = weekdays + tm.tm_wday * 3;
    month = months + tm.tm_mon * 3;

    r = snprintf(out, 30, "%.3s, %02d %.3s %04d %02d:%02d:%02d GMT", weekday,
                 tm.tm_mday, month, tm.tm_year + 1900, tm.tm_hour, tm.tm_min,
                 tm.tm_sec);
    if (UNLIKELY(r < 0 || r > 30))
        return -EINVAL;

    return 0;
}

/*
 * lwan - simple web server
 * Copyright (c) 2017 L. A. F. Pereira <l@tia.mat.br>
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
#include "int-to-str.h"

static int parse_2_digit_num_no_end_check(const char *str, unsigned int max)
{
    static const unsigned int tens[] = {0, 10, 20, 30, 40, 50, 60, 70, 80, 90};

    if (UNLIKELY(!lwan_char_isdigit(str[0])))
        return -EINVAL;
    if (UNLIKELY(!lwan_char_isdigit(str[1])))
        return -EINVAL;

    unsigned int val = tens[str[0] - '0'] + (unsigned int)(str[1] - '0');
    if (UNLIKELY(val > max))
        return -EINVAL;

    return (int)val;
}

static int
parse_2_digit_num(const char *str, const char end_chr, unsigned int max)
{
    if (UNLIKELY(str[2] != end_chr))
        return -EINVAL;
    return parse_2_digit_num_no_end_check(str, max);
}

int lwan_parse_rfc_time(const char in[static 30], time_t *out)
{
    /* This function is used instead of strptime() because locale
     * information can affect the parsing.  Instead of defining
     * the locale to "C", use hardcoded constants. */
    struct tm tm;
    const char *str = in;

    STRING_SWITCH(str) {
    case STR4_INT('S','u','n',','): tm.tm_wday = 0; break;
    case STR4_INT('M','o','n',','): tm.tm_wday = 1; break;
    case STR4_INT('T','u','e',','): tm.tm_wday = 2; break;
    case STR4_INT('W','e','d',','): tm.tm_wday = 3; break;
    case STR4_INT('T','h','u',','): tm.tm_wday = 4; break;
    case STR4_INT('F','r','i',','): tm.tm_wday = 5; break;
    case STR4_INT('S','a','t',','): tm.tm_wday = 6; break;
    default: return -EINVAL;
    }
    str += 5;

    tm.tm_mday = parse_2_digit_num(str, ' ', 31);
    if (UNLIKELY(tm.tm_mday <= 0))
        return -EINVAL;
    str += 3;

    STRING_SWITCH(str) {
    case STR4_INT('J','a','n',' '): tm.tm_mon = 0; break;
    case STR4_INT('F','e','b',' '): tm.tm_mon = 1; break;
    case STR4_INT('M','a','r',' '): tm.tm_mon = 2; break;
    case STR4_INT('A','p','r',' '): tm.tm_mon = 3; break;
    case STR4_INT('M','a','y',' '): tm.tm_mon = 4; break;
    case STR4_INT('J','u','n',' '): tm.tm_mon = 5; break;
    case STR4_INT('J','u','l',' '): tm.tm_mon = 6; break;
    case STR4_INT('A','u','g',' '): tm.tm_mon = 7; break;
    case STR4_INT('S','e','p',' '): tm.tm_mon = 8; break;
    case STR4_INT('O','c','t',' '): tm.tm_mon = 9; break;
    case STR4_INT('N','o','v',' '): tm.tm_mon = 10; break;
    case STR4_INT('D','e','c',' '): tm.tm_mon = 11; break;
    default: return -EINVAL;
    }
    str += 4;

    int year_hundreds = parse_2_digit_num_no_end_check(str, 21);
    int year_ones = parse_2_digit_num_no_end_check(str + 2, 99);
    if (UNLIKELY(year_hundreds < 0 || year_ones < 0))
        return -EINVAL;
    tm.tm_year = (year_hundreds * 100 + year_ones) - 1900;
    if (UNLIKELY(tm.tm_year < 0 || tm.tm_year > 1000))
        return -EINVAL;
    str += 5;

    tm.tm_hour = parse_2_digit_num(str, ':', 23);
    str += 3;
    tm.tm_min = parse_2_digit_num(str, ':', 59);
    str += 3;
    tm.tm_sec = parse_2_digit_num(str, ' ', 59);
    str += 3;

    STRING_SWITCH(str) {
    case STR4_INT('G','M','T','\0'):
        tm.tm_isdst = -1;

        *out = timegm(&tm);

        if (LIKELY(*out > 0))
            return 0;

        /* Fallthrough */
    default:
        return -EINVAL;
    }
}

static inline char *
append_two_digits(char *p, unsigned int digits)
{
    return mempcpy(p, uint_to_string_2_digits(digits), 2);
}

int lwan_format_rfc_time(const time_t in, char out[static 30])
{
    static const char *weekdays = "Sun,Mon,Tue,Wed,Thu,Fri,Sat,";
    static const char *months = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec ";
    struct tm tm;
    char *p;

    if (UNLIKELY(!gmtime_r(&in, &tm)))
        return -errno;

    p = mempcpy(out, weekdays + tm.tm_wday * 4, 4);
    *p++ = ' ';

    p = append_two_digits(p, (unsigned int)tm.tm_mday);
    *p++ = ' ';
    p = mempcpy(p, months + tm.tm_mon * 4, 4);

    tm.tm_year += 1900;
    p = append_two_digits(p, (unsigned int)tm.tm_year / 100);
    p = append_two_digits(p, (unsigned int)tm.tm_year % 100);

    *p++ = ' ';

    p = append_two_digits(p, (unsigned int)tm.tm_hour);
    *p++ = ':';
    p = append_two_digits(p, (unsigned int)tm.tm_min);
    *p++ = ':';
    p = append_two_digits(p, (unsigned int)tm.tm_sec);

    memcpy(p, " GMT", 5);

    return 0;
}

/* Dali Clock - a melting digital clock for PalmOS.
 * Copyright (c) 1991-2010 Jamie Zawinski <jwz@jwz.org>
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation.  No representations are made about the suitability of this
 * software for any purpose.  It is provided "as is" without express or
 * implied warranty.
 */

#ifdef LWAN_HAVE_CONFIG_H
#include "config.h"
#endif

#include "numbers.h"

#include "font/colonE.xbm"
#include "font/eightE.xbm"
#include "font/fiveE.xbm"
#include "font/fourE.xbm"
#include "font/nineE.xbm"
#include "font/oneE.xbm"
#include "font/sevenE.xbm"
#include "font/sixE.xbm"
#include "font/slashE.xbm"
#include "font/threeE.xbm"
#include "font/twoE.xbm"
#include "font/zeroE.xbm"
FONT(E);

const struct raw_number *get_raw_numbers(void) { return numbers_E; }

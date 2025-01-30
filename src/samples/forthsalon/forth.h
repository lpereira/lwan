/*
 * lwan - web server
 * Copyright (c) 2025 L. A. F. Pereira <l@tia.mat.br>
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

#pragma once

struct forth_ctx;

struct forth_vars {
    double x, y;
    double t, dt;
};

bool forth_run(struct forth_ctx *ctx, struct forth_vars *vars);
bool forth_parse_string(struct forth_ctx *ctx, const char *code);
void forth_free(struct forth_ctx *ctx);
struct forth_ctx *forth_new(void);
size_t forth_d_stack_len(const struct forth_ctx *ctx);
double forth_d_stack_pop(struct forth_ctx *ctx);





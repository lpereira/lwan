/*
 * lwan - simple web server
 * Copyright (c) 2018 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#include "lwan.h"
#include <stdlib.h>

#include "gifenc.h"

/* Font stolen from https://github.com/def-/time.gif */
static const uint8_t font[10][5] = {
    [0] = {7, 5, 5, 5, 7}, [1] = {2, 2, 2, 2, 2}, [2] = {7, 1, 7, 4, 7},
    [3] = {7, 1, 3, 1, 7}, [4] = {5, 5, 7, 1, 1}, [5] = {7, 4, 7, 1, 7},
    [6] = {7, 4, 7, 5, 7}, [7] = {7, 1, 1, 1, 1}, [8] = {7, 5, 7, 5, 7},
    [9] = {7, 5, 7, 1, 7},
};

static const uint16_t width = 24;
static const uint16_t height = 5;

static void destroy_gif(void *data)
{
    ge_GIF *gif = data;

    ge_close_gif(gif);
}

LWAN_HANDLER(clock)
{
    ge_GIF *gif = ge_new_gif(response->buffer, width, height, NULL, 2, 0);

    if (!gif)
        return HTTP_INTERNAL_ERROR;

    coro_defer(request->conn->coro, destroy_gif, gif);

    response->mime_type = "image/gif";
    response->headers = (struct lwan_key_value[]){
        {.key = "Content-Transfer-Encoding", .value = "binary"},
        {.key = "Cache-Control", .value = "no-cache"},
        {.key = "Cache-Control", .value = "no-store"},
        {.key = "Cache-Control", .value = "no-transform"},
        {},
    };

    memset(gif->frame, 0, (size_t)(width * height));

    while (true) {
        time_t curtime;
        char digits[8];
        int digit, line, base;

        curtime = time(NULL);
        strftime(digits, sizeof(digits), "%H%M%S", localtime(&curtime));

        for (digit = 0; digit < 6; digit++) {
            int dig = digits[digit] - '0';

            for (line = 0, base = digit * 4; line < 5; line++, base += width) {
                gif->frame[base + 0] = !!(font[dig][line] & 1<<2);
                gif->frame[base + 1] = !!(font[dig][line] & 1<<1);
                gif->frame[base + 2] = !!(font[dig][line] & 1<<0);
            }
        }

        ge_add_frame(gif, 100);
        lwan_response_send_chunk(request);
        lwan_request_sleep(request, 1000);
    }

    return HTTP_OK;
}

LWAN_HANDLER(index)
{
    static const char index[] = "<html><head>" \
        "<style>" \
        "body{background:black;height:100\x25;text-align:center;" \
        "border:0;margin:0;padding:0}" \
        "</style>" \
        "<title>Lwan Clock Sample</title>\n"
        "</head>" \
        "<body>" \
        "<table height=\"100\x25\" width=\"100\x25\">" \
        "<tr><td align=\"center\" valign=\"middle\">" \
        "<div><img style=\"image-rendering: pixelated; "\
        "image-rendering: -moz-crisp-edges; "\
        "image-rendering: crisp-edges;\" " \
        "src=\"/clock.gif\" width=\"200px\"></div>" \
        "</td></tr></table>" \
        "</body>" \
        "</html>";
    response->mime_type = "text/html";
    lwan_strbuf_set_static(response->buffer, index, sizeof(index) - 1);

    return HTTP_OK;
}

int main(void)
{
    const struct lwan_url_map default_map[] = {
        {.prefix = "/clock.gif", .handler = LWAN_HANDLER_REF(clock)},
        {.prefix = "/", .handler = LWAN_HANDLER_REF(index)},
        {.prefix = NULL},
    };
    struct lwan l;

    lwan_init(&l);

    lwan_set_url_map(&l, default_map);
    lwan_main_loop(&l);

    lwan_shutdown(&l);

    return 0;
}

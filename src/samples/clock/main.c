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

#include <stdlib.h>

#include "lwan.h"
#include "lwan-template.h"
#include "lwan-mod-redirect.h"
#include "gifenc.h"
#include "xdaliclock.h"
#include "blocks.h"

/* Font stolen from https://github.com/def-/time.gif */
static const uint8_t font[10][5] = {
    [0] = {7, 5, 5, 5, 7}, [1] = {2, 2, 2, 2, 2}, [2] = {7, 1, 7, 4, 7},
    [3] = {7, 1, 3, 1, 7}, [4] = {5, 5, 7, 1, 1}, [5] = {7, 4, 7, 1, 7},
    [6] = {7, 4, 7, 5, 7}, [7] = {7, 1, 1, 1, 1}, [8] = {7, 5, 7, 5, 7},
    [9] = {7, 5, 7, 1, 7},
};

static const struct lwan_key_value seriously_do_not_cache[] = {
    {.key = "Content-Transfer-Encoding", .value = "binary"},
    {.key = "Cache-Control", .value = "no-cache"},
    {.key = "Cache-Control", .value = "no-store"},
    {.key = "Cache-Control", .value = "no-transform"},
    {},
};

static const uint16_t width = 3 * 6 /* 6*3px wide digits */ +
                              3 * 1 /* 3*1px wide decimal digit space */ +
                              3 * 2 /* 2*3px wide minutes+seconds dots */;
static const uint16_t height = 5;

static void destroy_gif(void *data)
{
    ge_GIF *gif = data;

    ge_close_gif(gif);
}

LWAN_HANDLER(clock)
{
    static const uint8_t base_offsets[] = {0, 0, 2, 2, 4, 4};
    ge_GIF *gif = ge_new_gif(response->buffer, width, height, NULL, 2, -1);
    uint8_t dot_visible = 0;

    if (!gif)
        return HTTP_INTERNAL_ERROR;

    coro_defer(request->conn->coro, destroy_gif, gif);

    response->mime_type = "image/gif";
    response->headers = (struct lwan_key_value *)seriously_do_not_cache;

    memset(gif->frame, 0, (size_t)(width * height));

    for (int frame = 0; frame < 3600 * 2; frame++) {
        time_t curtime;
        char digits[8];
        int digit, line, base;

        curtime = time(NULL);
        strftime(digits, sizeof(digits), "%H%M%S", localtime(&curtime));

        for (digit = 0; digit < 6; digit++) {
            int dig = digits[digit] - '0';
            uint8_t off = base_offsets[digit];

            for (line = 0, base = digit * 4; line < 5; line++, base += width) {
                gif->frame[base + 0 + off] = !!(font[dig][line] & 1<<2);
                gif->frame[base + 1 + off] = !!(font[dig][line] & 1<<1);
                gif->frame[base + 2 + off] = !!(font[dig][line] & 1<<0);

            }
        }

        gif->frame[8 + width] = dot_visible;
        gif->frame[18 + width] = dot_visible;
        gif->frame[8 + width * 3] = dot_visible;
        gif->frame[18 + width * 3] = dot_visible;
        dot_visible = dot_visible ? 0 : 3;

        ge_add_frame(gif, 0);
        lwan_response_send_chunk(request);
        lwan_request_sleep(request, 500);
    }

    return HTTP_OK;
}

static void destroy_xdaliclock(void *data)
{
    struct xdaliclock *xdc = data;

    xdaliclock_free(xdc);
}

LWAN_HANDLER(dali)
{
    ge_GIF *gif = ge_new_gif(response->buffer, 320, 64, NULL, 2, -1);
    struct xdaliclock *xdc;
    uint32_t one_hour;

    if (!gif)
        return HTTP_INTERNAL_ERROR;

    coro_defer(request->conn->coro, destroy_gif, gif);

    xdc = xdaliclock_new(gif);
    if (!xdc)
        return HTTP_INTERNAL_ERROR;

    coro_defer(request->conn->coro, destroy_xdaliclock, xdc);

    response->mime_type = "image/gif";
    response->headers = seriously_do_not_cache;

    memset(gif->frame, 0, (size_t)(width * height));

    one_hour = 3600 * 1000 / xdaliclock_get_frame_time(xdc);
    for (uint32_t frame = 0; frame < one_hour; frame++) {
        xdaliclock_update(xdc);

        ge_add_frame(gif, 0);
        lwan_response_send_chunk(request);
        lwan_request_sleep(request, xdaliclock_get_frame_time(xdc));
    }

    return HTTP_OK;
}

LWAN_HANDLER(blocks)
{
    ge_GIF *gif = ge_new_gif(response->buffer, 32, 16, NULL, 4, -1);
    struct blocks blocks;
    uint64_t total_waited = 0;
    time_t last = 0;
    bool odd_second = false;

    if (!gif)
        return HTTP_INTERNAL_ERROR;

    coro_defer(request->conn->coro, destroy_gif, gif);

    blocks_init(&blocks, gif);

    response->mime_type = "image/gif";
    response->headers = seriously_do_not_cache;

    while (total_waited <= 3600000) {
        uint64_t timeout;
        time_t curtime;

        curtime = time(NULL);
        if (curtime != last) {
            char digits[5];

            strftime(digits, sizeof(digits), "%H%M", localtime(&curtime));
            last = curtime;
            odd_second = last & 1;

            for (int i = 0; i < 4; i++)
                blocks.states[i].num_to_draw = digits[i] - '0';
        }

        timeout = blocks_draw(&blocks, odd_second);
        total_waited += timeout;

        ge_add_frame(gif, 0);
        lwan_response_send_chunk(request);
        lwan_request_sleep(request, timeout);
    }

    return HTTP_OK;
}

struct index {
    const char *title;
    const char *variant;
    int width;
};

#undef TPL_STRUCT
#define TPL_STRUCT struct index
static const struct lwan_var_descriptor index_desc[] = {
    TPL_VAR_STR_ESCAPE(title),
    TPL_VAR_STR_ESCAPE(variant),
    TPL_VAR_INT(width),
    TPL_VAR_SENTINEL,
};

static struct lwan_tpl *index_tpl;

__attribute__((constructor)) static void initialize_template(void)
{
    static const char index[] =
        "<html>\n"
        "<head>\n"
        "<style>\n"
        "body {\n"
        "   background:black;\n"
        "   height:100\x25;\n"
        "   text-align:center;\n"
        "   border:0;\n"
        "   margin:0;\n"
        "   padding:0;\n"
        "   font-family: sans-serif;\n"
        "}\n"
        "img {\n"
        "   image-rendering: pixelated;\n"
        "   image-rendering: -moz-crisp-edges;\n"
        "   image-rendering: crisp-edges;\n"
        "}\n"
        "#styles {\n"
        "   color: #444;\n"
        "   top: 0;\n"
        "   position: absolute;\n"
        "   padding: 16px;\n"
        "   left: calc(50% - 100px - 16px);\n"
        "   width: 250px;\n"
        "}\n"
        "#styles a, #styles a:visited, #lwan a, #lwan a:visited { color: #666; }\n"
        "#lwan {\n"
        "   color: #555;\n"
        "   top: calc(100% - 40px);\n"
        "   position: absolute;\n"
        "   height: 20px;\n"
        "   font-size: 75%;\n"
        "   width: 300px;\n"
        "}\n"
        "</style>\n"
        "<meta http-equiv=\"Refresh\" content=\"3600;url=/{{variant}}\">\n"
        "<title>{{title}}</title>\n"
        "</head>\n"
        "<body>\n"
        "  <div id=\"lwan\">\n"
        "    Powered by the <a href=\"https://lwan.ws\">Lwan</a> web server.\n"
        "  </div>\n"
        "  <table height=\"100\x25\" width=\"100\x25\">\n"
        "  <tr>\n"
        "    <td align=\"center\" valign=\"middle\">\n"
        "    <div><img src=\"/{{variant}}.gif\" width=\"{{width}}px\"></div>\n"
        "    </td>\n"
        "  </tr>\n"
        "  </table>\n"
        "  <div id=\"styles\">\n"
        "    Styles: "
        "<a href=\"/clock\">Digital</a> &middot; "
        "<a href=\"/dali\">Dali</a> &middot; "
        "<a href=\"/blocks\">Blocks</a>\n"
        "  </div>\n"
        "</body>\n"
        "</html>";

    index_tpl = lwan_tpl_compile_string_full(index, index_desc,
                                             LWAN_TPL_FLAG_CONST_TEMPLATE);
    if (!index_tpl)
        lwan_status_critical("Could not compile template");
}

LWAN_HANDLER(templated_index)
{
    if (lwan_tpl_apply_with_buffer(index_tpl, response->buffer, data)) {
        response->mime_type = "text/html";
        return HTTP_OK;
    }

    return HTTP_INTERNAL_ERROR;
}

int main(void)
{
    struct index sample_clock = {
        .title = "Lwan Sample Clock",
        .variant = "clock",
        .width = 200,
    };
    struct index dali_clock = {
        .title = "Lwan Dali Clock",
        .variant = "dali",
        .width = 320,
    };
    struct index blocks_clock = {
        .title = "Lwan Blocks Clock",
        .variant = "blocks",
        .width = 320,
    };
    const struct lwan_url_map default_map[] = {
        {
            .prefix = "/clock.gif",
            .handler = LWAN_HANDLER_REF(clock),
        },
        {
            .prefix = "/dali.gif",
            .handler = LWAN_HANDLER_REF(dali),
        },
        {
            .prefix = "/blocks.gif",
            .handler = LWAN_HANDLER_REF(blocks),
        },
        {
            .prefix = "/clock",
            .handler = LWAN_HANDLER_REF(templated_index),
            .data = &sample_clock,
        },
        {
            .prefix = "/dali",
            .handler = LWAN_HANDLER_REF(templated_index),
            .data = &dali_clock,
        },
        {
            .prefix = "/blocks",
            .handler = LWAN_HANDLER_REF(templated_index),
            .data = &blocks_clock,
        },
        {
            .prefix = "/",
            REDIRECT("/clock"),
        },
        {},
    };
    struct lwan l;

    lwan_init(&l);

    lwan_set_url_map(&l, default_map);
    lwan_main_loop(&l);

    lwan_shutdown(&l);

    return 0;
}

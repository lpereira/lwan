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

#define _GNU_SOURCE
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>

#include "lwan.h"
#include "lwan-serve-files.h"

enum args {
  ARGS_FAILED,
  ARGS_USE_CONFIG,
  ARGS_SERVE_FILES
};

lwan_http_status_t
gif_beacon(lwan_request_t *request __attribute__((unused)),
           lwan_response_t *response,
           void *data __attribute__((unused)))
{
    /*
     * 1x1 transparent GIF image generated with tinygif
     * http://www.perlmonks.org/?node_id=7974
     */
    static const unsigned char gif_beacon_data[] = {
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x90,
        0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0xF9, 0x04,
        0x05, 0x10, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x04, 0x01
    };

    response->mime_type = "image/gif";
    strbuf_set_static(response->buffer, (char*)gif_beacon_data, sizeof(gif_beacon_data));

    return HTTP_OK;
}

lwan_http_status_t
test_chunked_encoding(lwan_request_t *request,
            lwan_response_t *response,
            void *data __attribute__((unused)))
{
    int i;

    response->mime_type = "text/plain";

    strbuf_printf(response->buffer, "Testing chunked encoding! First chunk\n");
    lwan_response_send_chunk(request);

    for (i = 0; i <= 10; i++) {
        strbuf_printf(response->buffer, "*This is chunk %d*\n", i);
        lwan_response_send_chunk(request);
    }

    strbuf_printf(response->buffer, "Last chunk\n");
    lwan_response_send_chunk(request);

    return HTTP_OK;
}

lwan_http_status_t
test_server_sent_event(lwan_request_t *request,
            lwan_response_t *response,
            void *data __attribute__((unused)))
{
    int i;

    for (i = 0; i <= 10; i++) {
        strbuf_printf(response->buffer, "Current value is %d", i);
        lwan_response_send_event(request, "currval");
    }

    return HTTP_OK;
}

lwan_http_status_t
hello_world(lwan_request_t *request,
            lwan_response_t *response,
            void *data __attribute__((unused)))
{
    static lwan_key_value_t headers[] = {
        { .key = "X-The-Answer-To-The-Universal-Question", .value = "42" },
        { NULL, NULL }
    };
    response->headers = headers;
    response->mime_type = "text/plain";

    const char *name = lwan_request_get_query_param(request, "name");
    if (name)
        strbuf_printf(response->buffer, "Hello, %s!", name);
    else
        strbuf_set_static(response->buffer, "Hello, world!", sizeof("Hello, world!") -1);

    const char *dump_vars = lwan_request_get_query_param(request, "dump_vars");
    if (!dump_vars)
        goto end;

    strbuf_append_str(response->buffer, "\n\nQuery String Variables\n", 0);
    strbuf_append_str(response->buffer, "----------------------\n\n", 0);

    lwan_key_value_t *qs = request->query_params.base;
    for (; qs->key; qs++)
        strbuf_append_printf(response->buffer,
                    "Key = \"%s\"; Value = \"%s\"\n", qs->key, qs->value);

    if (!(request->flags & REQUEST_METHOD_POST))
        goto end;

    strbuf_append_str(response->buffer, "\n\nPOST data\n", 0);
    strbuf_append_str(response->buffer, "---------\n\n", 0);

    for (qs = request->post_data.base; qs->key; qs++)
        strbuf_append_printf(response->buffer,
                    "Key = \"%s\"; Value = \"%s\"\n", qs->key, qs->value);

end:
    return HTTP_OK;
}

static enum args
parse_args(int argc, char *argv[], lwan_config_t *config, char **root)
{
  static const struct option opts[] = {
    { .name = "root", .has_arg = 1, .val = 'r' },
    { .name = "listen", .has_arg = 1, .val = 'l' },
    { .name = "help", .val = 'h' },
    { }
  };
  int c, optidx = 0;
  enum args result = ARGS_USE_CONFIG;

  while ((c = getopt_long(argc, argv, "hr:l:", opts, &optidx)) != -1) {
    switch (c) {
    case 'l':
      free(config->listener);
      config->listener = strdup(optarg);
      result = ARGS_SERVE_FILES;
      break;

    case 'r':
      free(*root);
      *root = strdup(optarg);
      result = ARGS_SERVE_FILES;
      break;

    default:
      printf("Run %s --help for usage information.\n", argv[0]);
      return ARGS_FAILED;

    case 'h':
      printf("Usage: %s [--root /path/to/root/dir] [--listener addr:port]\n", argv[0]);
      printf("\t[--config]\n");
      printf("Serve files through HTTP.\n\n");
      printf("Defaults to listening on all interfaces, port 8080, serving current directory.\n\n");
      printf("Options:\n");
      printf("\t-r, --root      Path to serve files from (default: current dir).\n");
      printf("\t-l, --listener  Listener (default: %s).\n", config->listener);
      printf("\t-h, --help      This.\n");
      printf("\n");
      printf("Examples:\n");
      printf("  Serve system-wide documentation: %s -r /usr/share/doc\n", argv[0]);
      printf("        Serve on a different port: %s -l '*:1337'\n", argv[0]);
      printf("\n");
      printf("Report bugs at <https://github.com/lpereira/lwan>.\n");
      return ARGS_FAILED;
    }
  }

  return result;
}

int
main(int argc, char *argv[])
{
    lwan_t l;
    lwan_config_t c;
    char *root = get_current_dir_name();

    c = *lwan_get_default_config();
    c.listener = strdup("*:8080");

    switch (parse_args(argc, argv, &c, &root)) {
    case ARGS_SERVE_FILES:
        lwan_status_info("Serving files from %s", root);
        lwan_init_with_config(&l, &c);

        const lwan_url_map_t map[] = {
            { .prefix = "/", SERVE_FILES(root) },
            { }
        };
        lwan_set_url_map(&l, map);
        break;
    case ARGS_USE_CONFIG:
        free(c.listener);
        free(root);

        lwan_init(&l);
        break;
    case ARGS_FAILED:
        return EXIT_FAILURE;
    }

    lwan_main_loop(&l);
    lwan_shutdown(&l);

    free(root);
}

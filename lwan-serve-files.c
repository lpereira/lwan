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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwan.h"
#include "lwan-sendfile.h"
#include "realpathat.h"

static void *serve_files_init(void *args);
static void serve_files_shutdown(void *data);
static lwan_http_status_t serve_files_handle_cb(lwan_request_t *request, lwan_response_t *response, void *data);

lwan_handler_t serve_files = {
    .init = serve_files_init,
    .shutdown = serve_files_shutdown,
    .handle = serve_files_handle_cb
};

struct serve_files_priv_t {
    char *root_path;
    size_t root_path_len;
    int root_fd;
};

static void *
serve_files_init(void *args)
{
    const char *root_path = args;
    char *canonical_root;
    int root_fd;
    struct serve_files_priv_t *priv;

    canonical_root = realpath(root_path, NULL);
    if (!canonical_root) {
        perror("serve_files_init");
        return false;
    }

    root_fd = open(canonical_root, O_RDONLY | O_NOATIME);
    if (root_fd < 0) {
        free(canonical_root);

        perror("serve_files_init");
        return NULL;
    }

    priv = malloc(sizeof(*priv));
    if (!priv) {
        free(canonical_root);
        close(root_fd);
        perror("serve_files_init");
        return NULL;
    }

    priv->root_path = canonical_root;
    priv->root_path_len = strlen(canonical_root);
    priv->root_fd = root_fd;
    return priv;
}

static void
serve_files_shutdown(void *data)
{
    struct serve_files_priv_t *priv = data;

    close(priv->root_fd);
    free(priv->root_path);
    free(priv);
}

static lwan_http_status_t
_serve_file_stream(lwan_request_t *request, void *data)
{
    char headers[512];
    lwan_http_status_t return_status;
    int file_fd;
    struct stat st;
    size_t header_len;
    struct serve_files_priv_t *priv = request->response.stream_content.priv;
    char *path = (char *)data + priv->root_path_len;

    if (*path)
        /* Non-empty path: skip first '/' so that openat() works as expected */
        ++path;
    else {
        /* Empty path: try serving up index.html by default */
        request->response.mime_type = "text/html";
        path = "index.html";
    }

    if (request->method == HTTP_HEAD) {
        /* No need to open the file if we're just interested in its metadata */
        if (UNLIKELY(fstatat(priv->root_fd, path, &st, 0) < 0)) {
            return_status = (errno == EACCES) ? HTTP_FORBIDDEN : HTTP_NOT_FOUND;
            goto end_no_close;
        }
    } else {
        if (UNLIKELY((file_fd = openat(priv->root_fd, path, O_RDONLY | O_NOATIME)) < 0)) {
            return_status = (errno == EACCES) ? HTTP_FORBIDDEN : HTTP_NOT_FOUND;
            goto end_no_close;
        }

        if (UNLIKELY(fstat(file_fd, &st) < 0)) {
            return_status = (errno == EACCES) ? HTTP_FORBIDDEN : HTTP_NOT_FOUND;
            goto end;
        }
    }

    if (S_ISDIR(st.st_mode)) {
        char *index_file;

        if (asprintf(&index_file, "%s/index.html", (char *)data) < 0) {
            return_status = HTTP_INTERNAL_ERROR;
            goto end;
        }

        close(file_fd);
        free(data);

        request->response.mime_type = "text/html";
        return _serve_file_stream(request, index_file);
    }

    request->response.content_length = st.st_size;
    header_len = lwan_prepare_response_header(request, HTTP_OK, headers);
    if (!header_len) {
        return_status = HTTP_INTERNAL_ERROR;
        goto end;
    }

    if (request->method == HTTP_HEAD) {
        if (UNLIKELY(write(request->fd, headers, header_len) < 0)) {
            perror("write");
            return_status = HTTP_INTERNAL_ERROR;
        } else
            return_status = HTTP_OK;
        goto end_no_close;
    }

    lwan_request_set_corked(request, true);

    if (UNLIKELY(write(request->fd, headers, header_len) < 0)) {
        perror("write");
        return_status = HTTP_INTERNAL_ERROR;
        goto end_corked;
    }

    if (UNLIKELY(lwan_sendfile(request, file_fd, 0, st.st_size) < 0))
        return_status = HTTP_INTERNAL_ERROR;
    else
        return_status = HTTP_OK;

end_corked:
    lwan_request_set_corked(request, false);
end:
    close(file_fd);
end_no_close:
    if (data != priv->root_path)
        free(data);

    return return_status;
}

static lwan_http_status_t
serve_files_handle_cb(lwan_request_t *request, lwan_response_t *response, void *data)
{
    lwan_http_status_t return_status = HTTP_OK;
    char *canonical_path;
    struct serve_files_priv_t *priv = data;

    if (UNLIKELY(!priv)) {
        return_status = HTTP_INTERNAL_ERROR;
        goto fail;
    }

    if (!*request->url.value) {
        canonical_path = priv->root_path;
        goto serve;
    }

    canonical_path = realpathat(priv->root_fd, priv->root_path, request->url.value, NULL);
    if (!canonical_path) {
        switch (errno) {
        case EACCES:
            return_status = HTTP_FORBIDDEN;
            goto fail;
        case ENOENT:
        case ENOTDIR:
            return_status = HTTP_NOT_FOUND;
            goto fail;
        }
        return_status = HTTP_BAD_REQUEST;
        goto fail;
    }

    if (strncmp(canonical_path, priv->root_path, priv->root_path_len)) {
        free(canonical_path);
        return_status = HTTP_FORBIDDEN;
        goto fail;
    }

serve:
    response->mime_type = (char*)lwan_determine_mime_type_for_file_name(canonical_path);
    response->stream_content.callback = _serve_file_stream;
    response->stream_content.data = canonical_path;
    response->stream_content.priv = priv;

    return return_status;

fail:
    response->stream_content.callback = NULL;
    return return_status;
}

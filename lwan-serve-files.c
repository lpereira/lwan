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

static lwan_http_status_t
_serve_file_stream(lwan_request_t *request, void *data)
{
    char headers[512];
    lwan_http_status_t return_status;
    int file_fd;
    struct stat st;
    size_t header_len;

    if (UNLIKELY((file_fd = open(data, O_RDONLY)) < 0)) {
        return_status = (errno == EACCES) ? HTTP_FORBIDDEN : HTTP_NOT_FOUND;
        goto end_no_close;
    }

    if (UNLIKELY(fstat(file_fd, &st) < 0)) {
        return_status = (errno == EACCES) ? HTTP_FORBIDDEN : HTTP_NOT_FOUND;
        goto end;
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
        goto end;
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
    free(data);

    return return_status;
}

lwan_http_status_t
serve_files(lwan_request_t *request, lwan_response_t *response, void *root_directory)
{
    lwan_http_status_t return_status = HTTP_OK;
    char *path_to_canonicalize;
    char *canonical_path;
    char *canonical_root;

    /* FIXME: ``canonical_root'' should be cached somewhere. */
    canonical_root = realpath(root_directory, NULL);
    if (!canonical_root)
        return (errno == EACCES) ? HTTP_FORBIDDEN : HTTP_INTERNAL_ERROR;

    if (UNLIKELY(asprintf(&path_to_canonicalize, "%s/%s",
                (char *)root_directory, request->url.value) < 0)) {
        return_status = HTTP_INTERNAL_ERROR;
        goto end;
    }

    canonical_path = realpath(path_to_canonicalize, NULL);
    free(path_to_canonicalize);
    if (!canonical_path) {
        switch (errno) {
        case EACCES:
            return_status = HTTP_FORBIDDEN;
            goto end;
        case ENOENT:
        case ENOTDIR:
            return_status = HTTP_NOT_FOUND;
            goto end;
        }
        return_status = HTTP_BAD_REQUEST;
        goto end;
    }

    if (strncmp(canonical_path, canonical_root, strlen(canonical_root))) {
        free(canonical_path);
        return_status = HTTP_FORBIDDEN;
        goto end;
    }

    response->mime_type = (char*)lwan_determine_mime_type_for_file_name(canonical_path);
    response->stream_content.callback = _serve_file_stream;
    response->stream_content.data = canonical_path;

    goto end_no_reset_stream_content;

end:
    response->stream_content.callback = NULL;

end_no_reset_stream_content:
    free(canonical_root);

    return return_status;
}

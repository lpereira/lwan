/*
 * lwan - web server
 * Copyright (c) 2022 L. A. F. Pereira <l@tia.mat.br>
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

/* Implementation of the Rack spec[1] for Lwan.  Not 100% functional yet.
 *
 * [1] https://github.com/rack/rack/blob/main/SPEC.rdoc
 *
 * Thanks to:
 *    https://silverhammermba.github.io/emberb/c/
 *    https://blog.peterzhu.ca/ruby-c-ext/
 *    https://brunosutic.com/blog/ruby-fiber-scheduler
 */

#ifndef NDEBUG
#define LWAN_DEBUG_MODE
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <ruby.h>
#include <ruby/thread.h>
#pragma GCC diagnostic pop
#undef ALWAYS_INLINE

#include <string.h>
#include <pthread.h>

#ifdef LWAN_DEBUG_MODE
#undef NDEBUG
#endif

#include "lwan-private.h"

#include "lwan-mod-ruby.h"

struct lwan_ruby_worker_thread {
    VALUE thread;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
    struct lwan_request *request;
    struct lwan_response *response;
    struct lwan_ruby_priv *priv;
    enum lwan_http_status status;
};

struct lwan_ruby_priv {
    struct lwan_ruby_worker_thread *threads;
    pthread_once_t thread_init_once;

    VALUE rackup;
    VALUE env;

    struct {
        VALUE input_stream;
        VALUE error_stream;
        VALUE logger;
    } klass;

    /* Pre-allocated strings to build environment variable */
    struct {
        VALUE content_length;
        VALUE http;
        VALUE https;
        VALUE path_info;
        VALUE query_string;
        VALUE request_method;
        VALUE script_name;
        VALUE server_port;
        VALUE server_protocol;
        VALUE rack_url_scheme;
        VALUE rack_input;
        VALUE rack_errors;
        VALUE proto_http_1_0;
        VALUE proto_http_1_1;

#define ENTRY(upper, lower, mask, constant, probability) VALUE method_##lower;
        FOR_EACH_REQUEST_METHOD(ENTRY)
#undef ENTRY

        VALUE last;
    } str;
};

static void lwan_ruby_print_errinfo(void)
{
 /*TODO: rewrite this! */
    VALUE lasterr = rb_gv_get("$!");
    VALUE inclass = rb_class_path(CLASS_OF(lasterr));
    VALUE message = rb_obj_as_string(lasterr);
    lwan_status_error("Error in %s: ``%s''",
             RSTRING_PTR(inclass), RSTRING_PTR(message));

    if (!NIL_P(rb_errinfo())) {
        lwan_status_error("Backtrace:");

        VALUE ary = rb_funcall(rb_errinfo(), rb_intern("backtrace"), 0);
        for (long c = 0; c < RARRAY_LEN(ary); ++c) {
            lwan_status_error("  %s", RSTRING_PTR(RARRAY_PTR(ary)[c]));
        }
    }
}

static inline VALUE static_strz(const char *str)
{
    return rb_str_new_static(str, (long)strlen(str));
}

static inline VALUE static_strval(const struct lwan_value *value)
{
    if (!value->value)
        return static_strz("");
    return rb_str_new_static(value->value, (long)value->len);
}

static VALUE lwan_ruby_require_try(VALUE pkg_name)
{
    const char *pkg = (char *)(uintptr_t)pkg_name;

    // rb_require?
    return rb_funcall(rb_cObject, rb_intern("require"), 1,
                      static_strz(pkg));
}

static inline bool lwan_ruby_require(const char *pkg)
{
    VALUE v;
    int status;

    v = rb_protect(lwan_ruby_require_try, (VALUE)(uintptr_t)pkg, &status);
    if (status != 0) {
        lwan_status_error("Exception while trying to require `%s'", pkg);
        lwan_ruby_print_errinfo();
        return false;
    }
    if (v == Qnil) {
        lwan_status_error("Requiring `%s' failed", pkg);
        return false;
    }

    return true;
}

static VALUE lwan_ruby_parse_script_try(VALUE script_value)
{
    struct lwan_strbuf *script = (struct lwan_strbuf *)(uintptr_t)script_value;
    VALUE builder, script_str, v;

    builder = rb_const_get(rb_const_get(rb_cObject, rb_intern("Rack")),
                           rb_intern("Builder"));

    script_str = rb_str_new_static(lwan_strbuf_get_buffer(script),
                             (long)lwan_strbuf_get_length(script));

    v = rb_funcall(builder, rb_intern("new_from_string"), 1, script_str);

    rb_str_free(script_str);

    return v;
}

static inline VALUE lwan_ruby_parse_script(const struct lwan_strbuf *script)
{
    VALUE v;
    int status;

    v = rb_protect(lwan_ruby_parse_script_try, (VALUE)(uintptr_t)script,
                   &status);
    if (status != 0) {
        lwan_status_error("Exception while parsing script");
        lwan_ruby_print_errinfo();
        return Qnil;
    }

    if (TYPE(v) == T_ARRAY) {
        if (RARRAY_LEN(v) < 1) {
            lwan_status_error("Rack.Builder#new_from_string returned an empty array");
            return Qnil;
        }

        v = RARRAY_PTR(v)[0];
    }

    return v;
}

static VALUE
lwan_ruby_parse_script_from_settings(const struct lwan_ruby_settings *settings)
{
    struct lwan_strbuf script;
    VALUE parsed_script;

    if (settings->script) {
        lwan_strbuf_init(&script);
        lwan_strbuf_set_staticz(&script, settings->script);

        parsed_script = lwan_ruby_parse_script(&script);

        lwan_strbuf_free(&script);

        return parsed_script;
    }

    if (settings->script_file) {
        if (!lwan_strbuf_init_from_file(&script, settings->script_file)) {
            lwan_status_error("Could not read from file %s",
                              settings->script_file);
            return Qnil;
        }

        parsed_script = lwan_ruby_parse_script(&script);

        lwan_strbuf_free(&script);

        return parsed_script;
    }

    lwan_status_error("`script` or `script_file` must be provided");
    return Qnil;
}

static bool lwan_ruby_create_env_strings(struct lwan_ruby_priv *priv)
{
    struct {
        const char *string;
        VALUE *value;
    } strings[] = {
        {"REQUEST_METHOD", &priv->str.request_method},
        {"SCRIPT_NAME", &priv->str.script_name},
        {"PATH_INFO", &priv->str.path_info},
        {"QUERY_STRING", &priv->str.query_string},
        {"SERVER_PORT", &priv->str.server_port},
        {"SERVER_PROTOCOL", &priv->str.server_protocol},
        {"CONTENT_LENGTH", &priv->str.content_length},
        {"rack.url_scheme", &priv->str.rack_url_scheme},
        {"rack.input", &priv->str.rack_input},
        {"rack.errors", &priv->str.rack_errors},
        {"HTTP/1.0", &priv->str.proto_http_1_0},
        {"HTTP/1.1", &priv->str.proto_http_1_1},
        {"http", &priv->str.http},
        {"https", &priv->str.https},
#define ENTRY(upper, lower, ...) {#upper, &priv->str.method_##lower},
        FOR_EACH_REQUEST_METHOD(ENTRY)
#undef ENTRY
        /* FIXME: what HTTP_* variables should we cache here? */
    };

    for (size_t i = 0; i < N_ELEMENTS(strings); i++) {
        *strings[i].value = static_strz(strings[i].string);
        if (*strings[i].value == Qnil) {
            lwan_status_error("Could not pre-initialize string: %s",
                              strings[i].string);
            return false;
        }

        *strings[i].value = rb_str_freeze(*strings[i].value);
        rb_gc_register_address(strings[i].value);
    }

    return true;
}

static const rb_data_type_t lwan_ruby_error_stream_type = {
    .wrap_struct_name = "LwanErrorStream",
    .flags = RUBY_TYPED_FREE_IMMEDIATELY,
};

static VALUE lwan_ruby_error_stream_puts(VALUE self, VALUE arg)
{
    if (TYPE(arg) != T_STRING) {
        if (!rb_respond_to(arg, rb_intern("to_s"))) {
            lwan_status_error("rack.errors#puts called without Object#to_s");
            return Qnil;
        }

        arg = rb_funcall(arg, rb_intern("to_s"), 0);
        if (TYPE(arg) != T_STRING) {
            lwan_status_error("rack.errors#puts called with Object#to_s that "
                              "doesn't return String");
            return Qnil;
        }
    }

    lwan_status_error("Ruby: %.*s", (int)RSTRING_LEN(arg), StringValuePtr(arg));

    return Qnil;
}

static VALUE lwan_ruby_error_stream_write(VALUE self, VALUE arg)
{
    return lwan_ruby_error_stream_puts(self, arg);
}

static VALUE lwan_ruby_error_stream_flush(VALUE self)
{
    return Qnil;
}

static VALUE lwan_ruby_create_error_stream_class_try(VALUE arg)
{
    VALUE error_stream = rb_define_class("LwanErrorStream", rb_cObject);

    /* SPEC: "puts must be called with a single argument that responds to to_s"
     */
    rb_define_method(error_stream, "puts", lwan_ruby_error_stream_puts, 1);

    /* SPEC: "write must be called with a single argument that is a String" */
    rb_define_method(error_stream, "write", lwan_ruby_error_stream_write, 1);

    /* SPEC: "flush must be called without arguments and must be called in order
     * to make the error appear for sure" */
    rb_define_method(error_stream, "flush", lwan_ruby_error_stream_flush, 0);

    return error_stream;
}

static inline VALUE lwan_ruby_create_error_stream_class(void)
{
    VALUE v;
    int status;

    v = rb_protect(lwan_ruby_create_error_stream_class_try, Qnil, &status);
    if (status != 0) {
        lwan_status_error("Exception raised while creating error stream class");
        return Qnil;
    }

    return v;
}

struct lwan_ruby_input_stream {
    struct lwan_request *request;
    struct lwan_value body;
};

static size_t lwan_ruby_input_stream_dsize(const void *data)
{
    return sizeof(struct lwan_ruby_input_stream);
}

static const rb_data_type_t lwan_ruby_input_stream_type = {
    .wrap_struct_name = "LwanInputStream",
    .function = {
        .dsize = lwan_ruby_input_stream_dsize,
        .dfree = RUBY_DEFAULT_FREE,
    },
    .flags = RUBY_TYPED_FREE_IMMEDIATELY,
};

static inline struct lwan_ruby_input_stream *
lwan_ruby_input_stream_get_stream_from_self(VALUE self)
{
    struct lwan_ruby_input_stream *stream;

    TypedData_Get_Struct(self, struct lwan_ruby_input_stream,
                         &lwan_ruby_input_stream_type, stream);

    return stream;
}

static VALUE lwan_ruby_input_stream_gets(VALUE self)
{
    struct lwan_ruby_input_stream *stream =
        lwan_ruby_input_stream_get_stream_from_self(self);

    if (!stream->body.len)
        return Qnil;

    char *end_of_line = memchr(stream->body.value, '\n', stream->body.len);
    if (!end_of_line) {
        const size_t old_len = stream->body.len;

        stream->body.len = 0;

        return rb_str_new_static(stream->body.value, (long)old_len);
    }

    const size_t new_len = (size_t)(end_of_line - stream->body.value);
    VALUE ret = rb_str_new_static(stream->body.value, (long)new_len);

    if (new_len == stream->body.len) {
        /* Don't go past the end of the buffer */
        stream->body.len = 0;
    } else {
        /* new_len + 1 to skip the \n so next invocation finds the next
         * line. */
        stream->body.value += new_len + 1;
        stream->body.len -= new_len + 1;
    }

    return ret;
}

static VALUE lwan_ruby_input_stream_read(VALUE self, VALUE args)
{
    struct lwan_ruby_input_stream *stream = lwan_ruby_input_stream_get_stream_from_self(self);
    VALUE *ptr_args;
    VALUE buffer = Qnil;
    size_t to_copy;
    bool return_nil_on_eof = false;

    assert(TYPE(args) == T_ARRAY);

    /* SPEC: "If given, length must be a non-negative Integer (>= 0) or nil,
     * and buffer must be a String and may not be nil." */
    if (RARRAY_LEN(args) >= 1) {
        ptr_args = RARRAY_PTR(args);

        /* SPEC: "(...) or nil */
        if (ptr_args[0] == Qnil) {
            /* SPEC: "If length is (...) nil, then this method reads
             * all data until EOF." */
            to_copy = stream->body.len;
        } else if (TYPE(ptr_args[0]) == T_FIXNUM) {
            /* SPEC: "If given, length must be a non-negative Integer (...)" */
            long length = NUM2LONG(ptr_args[0]);
            if (length < 0)
                return Qnil;

            to_copy = LWAN_MIN(stream->body.len, (size_t)length);

            /* SPEC: "When EOF is reached, this method returns nil if length is given and not nil" */
            return_nil_on_eof = true;
        } else {
            lwan_status_error("Call to input.read() with length of invalid type");
            return Qnil;
        }

        if (RARRAY_LEN(args) >= 2) {
            if (TYPE(ptr_args[1]) != T_STRING) {
                lwan_status_error("Buffer passed to input.read() isn't a string");
                return Qnil;
            }

            buffer = ptr_args[1];
        }
    } else {
        /* SPEC: "If length is not given (...), then this method reads
         * all data until EOF." */
        to_copy = stream->body.len;
    }

    if (!stream->body.len) {
        /* SPEC: "When EOF is reached, this method returns nil if length is
         * given and not nil, or “” if length is not given or is nil." */
        return return_nil_on_eof ? Qnil : static_strz("");
    }

    if (!to_copy)
        return static_strz("");

    assert(to_copy <= stream->body.len);

    if (buffer == Qnil)
        buffer = rb_str_buf_new((long)to_copy);

    rb_str_set_len(buffer, 0); /* set the string to "" before catting */
    rb_str_cat(buffer, stream->body.value, (long)to_copy);

    stream->body.len -= to_copy;
    stream->body.value += to_copy;

    return buffer;
}

static VALUE lwan_ruby_input_stream_each(VALUE self)
{
    /* FIXME: is raising an exception here if a block wasn't provided
     * the right thing to do? */
    rb_need_block();

    while (true) {
        VALUE line = lwan_ruby_input_stream_gets(self);

        if (line == Qnil)
            break;

        rb_yield(line);
    }

    return Qnil;
}

static VALUE lwan_ruby_input_stream_close(VALUE self)
{
    struct lwan_ruby_input_stream *stream =
        lwan_ruby_input_stream_get_stream_from_self(self);

    stream->body.len = 0;

    return self;
}

static VALUE lwan_ruby_input_stream_alloc(VALUE klass)
{
    struct lwan_ruby_input_stream *stream;

    stream = malloc(sizeof(*stream));
    if (!stream)
        return Qnil;

    return TypedData_Wrap_Struct(klass, &lwan_ruby_input_stream_type, stream);
}

static VALUE lwan_ruby_input_stream_initialize(VALUE self, VALUE val)
{
    struct lwan_ruby_input_stream *stream =
        lwan_ruby_input_stream_get_stream_from_self(self);
    struct lwan_request *request = (void *)(uintptr_t)val;

    stream->request = request;
    stream->body = *lwan_request_get_request_body(request);

    return self;
}

static VALUE lwan_ruby_input_stream_rewind(VALUE self)
{
    struct lwan_ruby_input_stream *stream =
        lwan_ruby_input_stream_get_stream_from_self(self);

    stream->body = *lwan_request_get_request_body(stream->request);

    return Qnil;
}

static VALUE lwan_ruby_create_input_stream_class_try(VALUE arg)
{
    /* FIXME: is this really needed? Or can we instantiate a StringIO object
     * with the body? */

    /* SPEC: "The input stream is an IO-like object which contains the raw
     * HTTP POST data."  */

    VALUE input_stream = rb_define_class("LwanInputStream", rb_cObject);

    rb_define_alloc_func(input_stream, lwan_ruby_input_stream_alloc);

    rb_define_method(input_stream, "initialize", lwan_ruby_input_stream_initialize, 1);

    /* This method isn't defined by the rack spec, but it's trivial to
     * implement so do it. */
    rb_define_method(input_stream, "rewind", lwan_ruby_input_stream_rewind, 0);

    /* SPEC: "gets must be called without arguments" */
    rb_define_method(input_stream, "gets", lwan_ruby_input_stream_gets, 0);

    /* SPEC: "read behaves like IO#read. Its signature is read([length,
     * [buffer]])" */
    rb_define_method(input_stream, "read", lwan_ruby_input_stream_read, -2);

    /* SPEC: "each must be called without arguments" */
    rb_define_method(input_stream, "each", lwan_ruby_input_stream_each, 0);
    
    /* SPEC: "close can be called on the input stream to indicate that the
     * any remaining input is not needed." */
    rb_define_method(input_stream, "close", lwan_ruby_input_stream_close, 0);

    return input_stream;
}

static inline VALUE lwan_ruby_create_input_stream_class(void)
{
    VALUE v;
    int status;

    v = rb_protect(lwan_ruby_create_input_stream_class_try, Qnil, &status);
    if (status != 0) {
        lwan_status_error("Exception raised while creating input stream class");
        return Qnil;
    }

    return v;
}

static VALUE lwan_ruby_create_env_try(VALUE arg)
{
    /* `env' contains the base environment; it'll be cloned (rb_hash_dup()?)
     * for each request and request-specific key/values will be added before
     * calling the ruby function to handle the request */
    VALUE env = rb_hash_new();

    rb_hash_aset(env, static_strz("SERVER_NAME"), static_strz("Lwan"));

    /* Provide means for an application to take control of the HTTP
     * connection.  This needs to be implemented in the future; let's
     * just say we don't support this for now and move on.
     * https://github.com/rack/rack/blob/main/SPEC.rdoc#label-Hijacking */
    rb_hash_aset(env, static_strz("rack.hijack?"), Qfalse);
    rb_hash_aset(env, static_strz("rack.hijack"), Qnil);

    /* This method must implement info(), debug(), warn(), error(),
     * and fatal(), all taking (message, &block) as parameters.  Put
     * nothing there at the moment. */
    rb_hash_aset(env, static_strz("rack.logger"), Qnil);

    /* Stores request session data. Has a tiny interface that has to
     * be implemented. Do nothing for now as it's underspecified. */
    rb_hash_aset(env, static_strz("rack.session"), Qnil);

    return env;
}

static inline VALUE lwan_ruby_create_env(void)
{
    VALUE v;
    int status;

    v = rb_protect(lwan_ruby_create_env_try, Qnil, &status);
    if (status != 0) {
        lwan_status_error("Exception raised while creating base environment");
        return Qnil;
    }

    return v;
}

static void *lwan_ruby_create(const char *prefix, void *args)
{
    static struct lwan_ruby_priv *priv;
    struct lwan_ruby_settings *settings = args;

    /* FIXME: this probably needs calls to rb_thread_create()? */

    if (priv) {
        lwan_status_error("Only one Ruby module instance allowed");
        return NULL;
    }

    priv = malloc(sizeof(*priv));
    if (!priv) {
        lwan_status_error("Could not allocate memory for Ruby module");
        return NULL;
    }

    priv->thread_init_once = PTHREAD_ONCE_INIT;


    return priv;

error:
    free(priv);
    priv = NULL;

    return NULL;
}

static void *lwan_ruby_create_from_hash(const char *prefix,
                                        const struct hash *hash)
{
    return lwan_ruby_create(prefix,
                            &(struct lwan_ruby_settings){
                                .script = hash_find(hash, "script"),
                                .script_file = hash_find(hash, "script_file"),
                            });
}

static void lwan_ruby_destroy(void *instance)
{
    struct lwan_ruby_priv *priv = instance;

    rb_gc_unregister_address(&priv->env);
    rb_gc_unregister_address(&priv->rackup);

    rb_gc_unregister_address(&priv->klass.input_stream);
    rb_gc_unregister_address(&priv->klass.error_stream);

    for (VALUE *v = &priv->str.content_length; v < &priv->str.last; v++) {
        /* FIXME: is this valid if these strings were frozen? */
        rb_gc_unregister_address(v);
    }

    free(priv);
}

struct lwan_ruby_priv_req {
    const struct lwan_ruby_priv *priv;
    const struct lwan_request *request;
};

static VALUE lwan_ruby_get_request_method(const struct lwan_ruby_priv *priv,
                                          const struct lwan_request *request)
{
#define ENTRY(upper, lower, mask, constant, probability)                       \
    case REQUEST_METHOD_##upper:                                               \
        return priv->str.method_##lower;

    switch (lwan_request_get_method(request)) {
        FOR_EACH_REQUEST_METHOD(ENTRY)
    default:
        return Qnil;
    }
#undef ENTRY
}

static void lwan_ruby_add_header_to_env_hash(const char *header,
                                             size_t header_len,
                                             const char *value,
                                             size_t value_len,
                                             void *user_data)
{
    VALUE env = (VALUE)(uintptr_t)user_data;

    /* FIXME: cache common header names! */

    /* Static strings are used here because the string pointers will
     * point to the request buffer and the string object will only
     * carry a pointer to them.  I'm not really sure if this is kosher,
     * especially when the GC is involved. */
    rb_hash_aset(env, rb_str_new_static(header, (long)header_len),
                 rb_str_new_static(value, (long)value_len));
}

static VALUE lwan_ruby_prepare_env_for_request_try(VALUE priv_req_val)
{
    const struct lwan_ruby_priv_req *priv_req =
        (const struct lwan_ruby_priv_req *)(uintptr_t)priv_req_val;
    const struct lwan_request *request = priv_req->request;
    const struct lwan_ruby_priv *priv = priv_req->priv;
    const struct lwan_request_parser_helper *request_helper = request->helper; 
    VALUE env;

    env = rb_hash_dup(priv->env);

    rb_hash_aset(env, priv->str.request_method,
                 lwan_ruby_get_request_method(priv, request));

    rb_hash_aset(env, priv->str.query_string,
                 static_strval(&request_helper->query_string));

    rb_hash_aset(env, priv->str.server_protocol,
                 (priv_req->request->flags & REQUEST_IS_HTTP_1_0)
                     ? priv->str.proto_http_1_0
                     : priv->str.proto_http_1_1);

    rb_hash_aset(env, priv->str.rack_url_scheme,
                 (priv_req->request->conn->flags & CONN_TLS) ? priv->str.https
                                                             : priv->str.http);

    lwan_request_foreach_header_for_cgi(priv_req->request,
                                        lwan_ruby_add_header_to_env_hash,
                                        (void *)(uintptr_t)env);

    VALUE input_stream =
        rb_class_new_instance(1, (VALUE[]){(VALUE)(uintptr_t)priv_req->request},
                              priv_req->priv->klass.input_stream);
    rb_hash_aset(env, priv->str.rack_input, input_stream);

/*
    VALUE error_stream = rb_class_new_instance(0, (VALUE[]){},
            priv_req->priv->klass.error_stream);
    rb_hash_aset(env, priv->str.rack_errors, error_stream);
*/
    return env;
}

static inline VALUE
lwan_ruby_prepare_env_for_request(const struct lwan_ruby_priv *priv,
                                  const struct lwan_request *request)
{
    const struct lwan_ruby_priv_req priv_req = {.priv = priv,
                                                .request = request};
    int status;
    VALUE v;

    v = rb_protect(lwan_ruby_prepare_env_for_request_try,
                   (VALUE)(uintptr_t)&priv_req,
                   &status);
    if (status != 0) {
        lwan_status_error(
            "Exception raised while preparing environment to service request");
        return Qnil;
    }

    return v;
}

struct lwan_ruby_priv_env {
    const struct lwan_ruby_priv *priv;
    VALUE env;
};

static VALUE lwan_ruby_call_app_try(VALUE priv_env_value)
{
    struct lwan_ruby_priv_env *priv_env =
        (struct lwan_ruby_priv_env *)(uintptr_t)priv_env_value;
    return rb_funcall(rb_cObject, rb_intern("call"), 1, priv_env->env);
}

static inline VALUE lwan_ruby_call_app(const struct lwan_ruby_priv *priv,
                                       VALUE env)
{
    VALUE v;
    int status;
    struct lwan_ruby_priv_env priv_env = {.priv = priv, .env = env};

    v = rb_protect(lwan_ruby_call_app_try, (VALUE)(uintptr_t)&priv_env,
                   &status);
    if (status != 0) {
        lwan_status_error("Exception raised while calling app");
        return Qnil;
    }

    return v;
}

static bool lwan_ruby_add_header_to_array(struct lwan_key_value_array *kva,
                                          const char *key,
                                          const char *value)
{
    /* Spec: "(...) such that each String instance must not contain
     * characters below 037." */
    for (const char *p = value; *p; p++) {
        if (UNLIKELY(*p < 037))
            return false;
    }

    struct lwan_key_value *kv = lwan_key_value_array_append(kva);
    if (LIKELY(kv)) {
        *kv = (struct lwan_key_value){
            .key = (char *)key,
            .value = (char *)value,
        };
        return true;
    }

    return false;
}

static inline bool lwan_ruby_is_valid_char_for_header(char c)
{
    /* Table generated with this C program:
     *   for (int i = 0; i < 256; i++) {
     *       if (isprint(i) && !strchr("(),/:;<=>?@[]{}\"", i) && !isupper(i))
     *           table[i / 32] |= 1 << (i % 32);
     *   }
     */
    unsigned char uc = (unsigned char)c;
    static const unsigned int table[] = {0, 0x3ff6cfb, 0xd0000000, 0x57ffffff,
                                         0, 0,         0,          0};
    return table[uc >> 5] & 1 << (uc & 31);
}

static int lwan_ruby_add_headers_to_array(VALUE key, VALUE value, VALUE data)
{
    struct lwan_key_value_array *kva = (void *)(uintptr_t)data;

    /* Spec: "The header keys must be Strings" */
    if (UNLIKELY(TYPE(key) != T_STRING))
        return ST_STOP;

    const char *k = StringValueCStr(key);

    /* Spec: "Special headers starting “rack.” are for communicating with
     * the server, and must not be sent back to the client" */
    if (UNLIKELY(!strncmp(k, "rack.", 5)))
        return ST_CONTINUE;

    /* Spec: "The header must not contain a Status key." */
    if (UNLIKELY(strcaseequal_neutral(k, "Status")))
        return ST_CONTINUE;

    /* TODO per spec: content-type and content-length headers must not be
       present if the status is 1xx, 204, or 304.  */

    /* Spec: "Header keys must conform to RFC7230 token specification, i.e.
     * cannot contain non-printable ASCII, DQUOTE or “(),/:;<=>?@[]{}”.
     * Header keys must not contain uppercase ASCII characters (A-Z)." */
    for (const char *p = k; *p; p++) {
        if (!lwan_ruby_is_valid_char_for_header(*p)) {
            lwan_status_warning("Ignoring non-standard header `%s'", k);
            return ST_CONTINUE;
        }
    }

    if (TYPE(value) == T_STRING) {
        /* Spec: "Header values must be either a String instance, (...)"*/
        if (!lwan_ruby_add_header_to_array(kva, k, StringValueCStr(value)))
            return ST_STOP;
    } else if (TYPE(value) == T_ARRAY) {
        /* Spec: "(...) or an Array of String instances." */
        const long len = rb_array_len(value);
        VALUE *array = RARRAY_PTR(value);

        for (long i = 0; i < len; i++) {
            if (TYPE(array[i]) != T_STRING) {
                lwan_status_error("Item %ld for header %s isn't a string", i,
                                  k);
                return ST_STOP;
            }

            const char *v = StringValueCStr(array[i]);
            if (!lwan_ruby_add_header_to_array(kva, k, v))
                return ST_STOP;
        }
    } else {
        lwan_status_error("Expecting a string or array for header `%s`", k);
        return ST_STOP;
    }

    return ST_CONTINUE;
}

static void *lwan_ruby_body_write_unlocked(void *data)
{
    struct lwan_request *request = data;

    /* TODO: can we know that this is the last chunk from body?
     * if so, all other chunks could be sent with MSG_MORE and
     * the last one without it so we flush the last fragment. */
    lwan_response_send_chunk(request);

    return NULL;
}

static VALUE lwan_ruby_body_iter(VALUE yielded_arg,
                                 VALUE callback_arg,
                                 int argc,
                                 const VALUE *argv,
                                 VALUE block_arg)
{
    struct lwan_request *request = (void *)(uintptr_t)callback_arg;

    if (TYPE(yielded_arg) == T_STRING) {
        lwan_strbuf_set_static(request->response.buffer,
                               RSTRING_PTR(yielded_arg),
                               (size_t)RSTRING_LEN(yielded_arg));

        /* FIXME: Calling a funciton without the GVL has a cost; maybe we
         * should buffer the whole response rather than use chunked
         * encoding?  */
        rb_thread_call_without_gvl(lwan_ruby_body_write_unlocked,
                                   (void *)(uintptr_t)request,
                                   RUBY_UBF_IO, NULL);
    } else {
        lwan_status_warning("Body item isn't string, ignoring");
    }

    return Qnil;
}


static enum lwan_http_status lwan_ruby_worker_handle_one_request(
    struct lwan_request *request,
    struct lwan_response  *response,
    struct lwan_ruby_priv *priv) {
    /* FIXME: this should be in a ruby thread.  to make this work,
     * we need to:
     *    have a thread-local ptr to a ruby thread
     *        probably use get_specific to have instance ptr in instance
     *    have a pthread_cond_t or something of the sort so
     *        the ruby thread can wait
     *        this thread can set a pointer to the request/response/instance
     *        this thread can then signal so that the ruby thread can run this code
     *        this thread then needs to wait on another cond to get the response code
     *        once the ruby thread is done, it signals this thread
     * otherwise, this will fail inside rb_protect() because there's no 
     * execution context for the worker thread.
     * the pthread_cond_t could be something that uses the main loop
     * instead, such as something that uses eventfd and waits for it to be
     * written to or something.  this might scale better as the thread doesn't
     * need to block (other threads might be waiting to be serviced!).  do this
     * later once the pthread_cond_t thing works. */

    /* FIXME: this should really use a FiberScheduler that ties with our
     * coroutine implementation! */

    /* FIXME: this should be wrapped in multiple rb_protect() calls to avoid
     * exceptions!  */

    VALUE env = lwan_ruby_prepare_env_for_request(priv, request);

    /* Spec: "It takes exactly one argument, the environment, (...)" */
    VALUE tuple = lwan_ruby_call_app(priv, env);

    /* Spec: "(...) and returns a non-frozen Array of exactly three values:
     * The status, the headers, and the body." */
    if (UNLIKELY(TYPE(tuple) != T_ARRAY)) {
        lwan_status_error(
            "Application returned something other than a 3-tuple");
        return HTTP_INTERNAL_ERROR;
    }
    if (UNLIKELY(RARRAY_LEN(tuple) != 3)) {
        lwan_status_error(
            "Application returned an array with %ld elements; expecting 3",
            RARRAY_LEN(tuple));
        return HTTP_INTERNAL_ERROR;
    }

    VALUE *tuple_values = RARRAY_PTR(tuple);

    /* Spec: "This is an HTTP status. It must be an Integer greater than or
     * equal to 100." */
    if (UNLIKELY(TYPE(tuple_values[0]) != T_FIXNUM)) {
        lwan_status_error("Status code isn't a number");
        return HTTP_INTERNAL_ERROR;
    }
    enum lwan_http_status status =
        (enum lwan_http_status)FIX2INT(tuple_values[0]);
    if (UNLIKELY(status < 100 || status > 600)) {
        lwan_status_error("Application returned an invalid status code");
        return HTTP_INTERNAL_ERROR;
    }

    /* Spec: "The headers must be a unfrozen Hash." */
    if (UNLIKELY(TYPE(tuple_values[1]) != T_HASH)) {
        lwan_status_error("Headers isn't a hash table!");
        return HTTP_INTERNAL_ERROR;
    }
    struct lwan_key_value_array *headers =
        coro_lwan_key_value_array_new(request->conn->coro);
    if (UNLIKELY(!headers)) {
        lwan_status_error("Could not allocate headers array");
        return HTTP_INTERNAL_ERROR;
    }
    rb_hash_foreach(tuple_values[1], lwan_ruby_add_headers_to_array,
                    (VALUE)(uintptr_t)headers);
    struct lwan_key_value *empty_kv = lwan_key_value_array_append(headers);
    if (!empty_kv)
        return HTTP_INTERNAL_ERROR;
    *empty_kv = (struct lwan_key_value){};

    /* Body stuff */
    if (TYPE(tuple_values[2]) == T_ARRAY) {
        /* FIXME: is this better than using rb_block_call? */
        VALUE *body = RARRAY_PTR(tuple_values[2]);
        long len = RARRAY_LEN(tuple_values[2]);

        for (long i = 0; i < len; i++) {
            if (TYPE(body[i]) != T_STRING)
                return HTTP_INTERNAL_ERROR;

            lwan_strbuf_append_str(response->buffer, RSTRING_PTR(body[i]),
                                   (size_t)RSTRING_LEN(body[i]));
        }

        response->headers = lwan_key_value_array_get_array(headers);
    } else if (rb_respond_to(tuple_values[2], rb_intern("each"))) {
        /* Spec: "A Body that responds to each is considered to be an
         * Enumerable Body." */
        response->headers = lwan_key_value_array_get_array(headers);
        lwan_response_set_chunked(request, status);

        rb_block_call(tuple_values[2], rb_intern("each"), 0, NULL,
                      lwan_ruby_body_iter, (VALUE)(uintptr_t)request);
    } else {
        /* Spec: "If the Body responds to to_path, it must return a String
         * path for the local file system whose contents are identical to
         * that produced by calling each": this will be implemented only if
         * necessary; it doesn't seem to be used often. */

        /* Spec: "A Body that responds to call is considered to be a
         * Streaming Body.": this also doesn't seem to be often used, so
         * I'll implement this only if necessary. */

        return HTTP_INTERNAL_ERROR;
    }

    /* FIXME: do we need to check for this even if the body is an array? */
    if (rb_respond_to(tuple_values[2], rb_intern("close")))
        rb_funcall(tuple_values[2], rb_intern("close"), 1, Qnil);

    return status;
}

static VALUE lwan_ruby_worker_thread(void *data)
{
    struct lwan_ruby_worker_thread_state *state = data;

    lwan_status_debug("worker thread created");

    while (true) {
        lwan_status_debug("waiting for cond");
        pthread_cond_wait(&state->cond, &state->mutex);

        lwan_status_debug("cond signaled, handling one request");

        state->status = lwan_ruby_worker_handle_one_request(
            state->request, state->response, state->priv);

        lwan_status_debug("request handled, signaling handler");

        pthread_cond_signal(&state->cond);
    }

    return Qnil;
}

static void lwan_ruby_create_thread_once(
    RUBY_INIT_STACK
    if (ruby_setup()) {
        free(priv);
        lwan_status_error("Could not setup Ruby");
        return NULL;
    }
    ruby_options(2, (char *[]){"Lwan", "-e0"});
    ruby_script("Lwan");
    ruby_init_loadpath();

    priv->klass.input_stream = lwan_ruby_create_input_stream_class();
    if (priv->klass.input_stream == Qnil)
        lwan_status_critical("Could not create input stream class");
    rb_gc_register_address(&priv->klass.input_stream);

    priv->klass.error_stream = lwan_ruby_create_error_stream_class();
    if (priv->klass.error_stream == Qnil)
        lwan_status_critical("Could not create error stream class");
    rb_gc_register_address(&priv->klass.error_stream);

    if (!lwan_ruby_create_env_strings(priv))
        lwan_status_critical("Could not pre-create strings");

    if (!lwan_ruby_require("rubygems"))
        lwan_status_critical("Could not require rubygems");
    if (!lwan_ruby_require("bundler/setup"))
        lwan_status_critical("Could not require bundler/setup");
    if (!lwan_ruby_require("rack"))
        lwan_status_critical("Could not require rack");

    priv->rackup = lwan_ruby_parse_script_from_settings(settings);
    if (priv->rackup == Qnil) {
        lwan_status_error("Could not parse script");
        goto error;
    }
    rb_gc_register_address(&priv->rackup);

    priv->env = lwan_ruby_create_env();
    if (priv->env == Qnil) {
        lwan_status_error("Could not create environment");
        goto error;
    }
    rb_gc_register_address(&priv->env);


static enum lwan_http_status
lwan_ruby_handle_request(struct lwan_request *request,
                         struct lwan_response *response,
                         void *instance)
{
    struct lwan_ruby_priv *priv = instance;
    static __thread VALUE thread = Qnil;
    static __thread struct lwan_ruby_worker_thread_state state = {
        .mutex = PTHREAD_MUTEX_INITIALIZER,
    };

    if (thread == Qnil) {
        /* this doesn't work here: rb_thread_create() *has* to be created
         * from the main fucking thread. sigh. */
        thread = rb_thread_create(lwan_ruby_worker_thread, &state);
    }

    state.request = request;
    state.response = response;
    state.priv = priv;
    pthread_cond_signal(&state.cond);

    pthread_cond_wait(&state.cond, &state.mutex);

    return state.status;
}

static const struct lwan_module module = {
    .create = lwan_ruby_create,
    .create_from_hash = lwan_ruby_create_from_hash,
    .parse_conf = NULL,
    .destroy = lwan_ruby_destroy,
    .handle_request = lwan_ruby_handle_request,
    .flags = 0,
};

LWAN_REGISTER_MODULE(rack, &module);

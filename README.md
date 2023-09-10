Lwan Web Server
===============

Lwan is a **high-performance** & **scalable** web server.

The [project web site](https://lwan.ws/) contains more details.

Build status
------------

| OS          | Arch   | Release | Debug | Static Analysis | Tests |
|-------------|--------|---------|-------|-----------------|------------|
| Linux       | x86_64 | ![release](https://shield.lwan.ws/img/gycKbr/release "Release")  | ![debug](https://shield.lwan.ws/img/gycKbr/debug "Debug")     | ![static-analysis](https://shield.lwan.ws/img/gycKbr/clang-analyze "Static Analysis") ![coverity](https://scan.coverity.com/projects/375/badge.svg) [Report history](https://buildbot.lwan.ws/sa/) | ![tests](https://shield.lwan.ws/img/gycKbr/unit-tests "Test") [![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/lwan.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:lwan)           |
| Linux       | armv7  | ![release-arm](https://shield.lwan.ws/img/gycKbr/release-arm "Release")  | ![debug-arm](https://shield.lwan.ws/img/gycKbr/debug-arm "Debug")     |        |           |
| FreeBSD     | x86_64 | ![freebsd-release](https://shield.lwan.ws/img/gycKbr/release-freebsd "Release FreeBSD") | ![freebsd-debug](https://shield.lwan.ws/img/gycKbr/debug-freebsd "Debug FreeBSD")     |                |           |
| macOS       | x86_64 | ![osx-release](https://shield.lwan.ws/img/gycKbr/release-sierra "Release macOS")       | ![osx-debug](https://shield.lwan.ws/img/gycKbr/debug-sierra "Debug macOS")     |               |          |
| OpenBSD 6.6 | x86_64 | ![openbsd-release](https://shield.lwan.ws/img/gycKbr/release-openbsd "Release OpenBSD")       | ![openbsd-debug](https://shield.lwan.ws/img/gycKbr/debug-openbsd "Debug OpenBSD")     |               | ![openbsd-tests](https://shield.lwan.ws/img/gycKbr/openbsd-unit-tests "OpenBSD Tests")         |

Installing
----------

You can either [build Lwan yourself](#Building), use a [container
image](#container-images), or grab a package from [your favorite
distribution](#lwan-in-the-wild).

Building
--------

Before installing Lwan, ensure all dependencies are installed. All of them
are common dependencies found in any GNU/Linux distribution; package names
will be different, but it shouldn't be difficult to search using whatever
package management tool that's used by your distribution.

### Required dependencies

 - [CMake](https://cmake.org/), at least version 2.8
 - [ZLib](http://zlib.net)

### Optional dependencies

The build system will look for these libraries and enable/link if available.

 - [Lua 5.1](http://www.lua.org) or [LuaJIT 2.0](http://luajit.org)
 - [Valgrind](http://valgrind.org)
 - [Brotli](https://github.com/google/brotli)
    - Can be disabled by passing `-DENABLE_BROTLI=NO`
 - [ZSTD](https://github.com/facebook/zstd)
    - Can be disabled by passing `-DENABLE_ZSTD=NO`
 - On Linux builds, if `-DENABLE_TLS=ON` (default) is passed:
    - [mbedTLS](https://github.com/ARMmbed/mbedtls)
 - Alternative memory allocators can be used by passing `-DUSE_ALTERNATIVE_MALLOC` to CMake with the following values:
    - ["mimalloc"](https://github.com/microsoft/mimalloc)
    - ["jemalloc"](http://jemalloc.net/)
    - ["tcmalloc"](https://github.com/gperftools/gperftools)
    - "auto": Autodetect from the list above, falling back to libc malloc if none found
 - To run test suite:
    - [Python](https://www.python.org/) (2.6+) with Requests
    - [Lua 5.1](http://www.lua.org)
 - To run benchmark:
    - [Weighttp](https://github.com/lpereira/weighttp) -- bundled and built alongside Lwan for convenience
    - [Matplotlib](https://github.com/matplotlib/matplotlib)
 - To build TechEmpower benchmark suite:
    - Client libraries for either [MySQL](https://dev.mysql.com) or [MariaDB](https://mariadb.org)
    - [SQLite 3](http://sqlite.org)

> :bulb: **Note:** On some systems,
> [libucontext](https://github.com/kaniini/libucontext) will be downloaded
> and built alongside Lwan.  This will require a network connection, so keep
> this in mind when packaging Lwan for non-x86_64 or non-aarch64
> architectures.

### Common operating system package names

#### Minimum to build
 - ArchLinux: `pacman -S cmake zlib`
 - FreeBSD: `pkg install cmake pkgconf`
 - Ubuntu 14+: `apt-get update && apt-get install git cmake zlib1g-dev pkg-config`
 - macOS: `brew install cmake`

#### Build with all optional features
 - ArchLinux: `pacman -S cmake zlib sqlite luajit libmariadbclient gperftools valgrind mbedtls`
 - FreeBSD: `pkg install cmake pkgconf sqlite3 lua51`
 - Ubuntu 14+: `apt-get update && apt-get install git cmake zlib1g-dev pkg-config lua5.1-dev libsqlite3-dev libmysqlclient-dev libmbedtls-dev`
 - macOS: `brew install cmake mysql-connector-c sqlite lua@5.1 pkg-config`

### Build commands

#### Clone the repository

    ~$ git clone git://github.com/lpereira/lwan
    ~$ cd lwan

#### Create the build directory

    ~/lwan$ mkdir build
    ~/lwan$ cd build

#### Select build type

Selecting a *release* version (no debugging symbols, messages, enable some
optimizations, etc):

    ~/lwan/build$ cmake .. -DCMAKE_BUILD_TYPE=Release

If you'd like to enable optimizations but still use a debugger, use this instead:

    ~/lwan/build$ cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo

To disable optimizations and build a more debugging-friendly version:

    ~/lwan/build$ cmake .. -DCMAKE_BUILD_TYPE=Debug

#### Build Lwan

    ~/lwan/build$ make

This will generate a few binaries:

 - `src/bin/lwan/lwan`: The main Lwan executable. May be executed with `--help` for guidance.
 - `src/bin/testrunner/testrunner`: Contains code to execute the test suite.
 - `src/samples/freegeoip/freegeoip`: [FreeGeoIP sample implementation](https://freegeoip.lwan.ws). Requires SQLite.
 - `src/samples/techempower/techempower`: Code for the TechEmpower Web Framework benchmark. Requires SQLite and MySQL libraries.
 - `src/samples/clock/clock`: [Clock sample](https://time.lwan.ws). Generates a GIF file that always shows the local time.
 - `src/bin/tools/mimegen`: Builds the extension-MIME type table. Used during build process.
 - `src/bin/tools/bin2hex`: Generates a C file from a binary file, suitable for use with #include.
 - `src/bin/tools/configdump`: Dumps a configuration file using the configuration reader API.
 - `src/bin/tools/weighttp`: Rewrite of the `weighttp` HTTP benchmarking tool.

#### Remarks

Passing `-DCMAKE_BUILD_TYPE=Release` will enable some compiler
optimizations (such as [LTO](http://gcc.gnu.org/wiki/LinkTimeOptimization))
and tune the code for current architecture.

> :exclamation: **Important:** *Please use the release build when benchmarking*, as
> the default is the Debug build, which not only logs all requests to the
> standard output, but does so while holding a lock, severely holding down
> the server.

The default build (i.e. not passing `-DCMAKE_BUILD_TYPE=Release`) will build
a version suitable for debugging purposes.  This version can be used under
Valgrind *(if its headers are present)* and includes debugging messages that
are stripped in the release version.  Debugging messages are printed for
each and every request.

On debug builds, sanitizers can be enabled.  To select which one to build Lwan
with, specify one of the following options to the CMake invocation line:

 - `-DSANITIZER=ubsan` selects the Undefined Behavior Sanitizer.
 - `-DSANITIZER=address` selects the Address Sanitizer.
 - `-DSANITIZER=thread` selects the Thread Sanitizer.

Alternative memory allocators can be selected as well.  Lwan currently
supports [TCMalloc](https://github.com/google/tcmalloc),
[mimalloc](https://github.com/microsoft/mimalloc), and
[jemalloc](http://jemalloc.net/) out of the box.  To use either one of them,
pass `-DALTERNATIVE_MALLOC=name` to the CMake invocation line, using the
names provided in the "Optional dependencies"  section.

The `-DUSE_SYSLOG=ON` option can be passed to CMake to also log to the system log
in addition to the standard output.

If you're building Lwan for a distribution, it might be wise to use the
`-DMTUNE_NATIVE=OFF` option, otherwise the generated binary may fail to
run on some computers.

### Tests

    ~/lwan/build$ make testsuite

This will compile the `testrunner` program and execute regression test suite
in `src/scripts/testsuite.py`.

### Benchmark

    ~/lwan/build$ make benchmark

This will compile `testrunner` and execute benchmark script
`src/scripts/benchmark.py`.

### Coverage

Lwan can also be built with the Coverage build type by specifying
`-DCMAKE_BUILD_TYPE=Coverage`.  This enables the `generate-coverage` make
target, which will run `testrunner` to prepare a test coverage report with
[lcov](http://ltp.sourceforge.net/coverage/lcov.php).

Every commit in this repository triggers the generation of this report,
and results are [publicly available](https://buildbot.lwan.ws/lcov/).

Running
-------

Set up the server by editing the provided `lwan.conf`; the format is
explained in details below.

> :bulb: **Note:** Lwan will try to find a configuration file based in the
> executable name in the current directory; `testrunner.conf` will be used
> for the `testrunner` binary, `lwan.conf` for the `lwan` binary, and so on.

Configuration files are loaded from the current directory. If no changes
are made to this file, running Lwan will serve static files located in
the `./wwwroot` directory. Lwan will listen on port 8080 on all interfaces.

Lwan will detect the number of CPUs, will increase the maximum number of
open file descriptors and generally try its best to autodetect reasonable
settings for the environment it's running on.  Many of these settings can
be tweaked in the configuration file, but it's usually a good idea to not
mess with them.

> :magic_wand: **Tip:** Optionally, the `lwan` binary can be used for one-shot
> static file serving without any configuration file.  Run it with `--help`
> for help on that.

Configuration File
----------------

### Format

Lwan uses a familiar `key = value` configuration file syntax.  Comments are
supported with the `#` character (similar to e.g.  shell scripts, Python,
and Perl).  Nested sections can be created with curly brackets.  Sections
can be empty; in this case, curly brackets are optional.

`some_key_name` is equivalent to `some key name` in configuration files (as
an implementation detail, code reading configuration options will only be
given the version with underscores).

> :magic_wand: **Tip:** Values can contain environment variables. Use the
> syntax `${VARIABLE_NAME}`.  Default values can be specified with a colon
> (e.g.  `${VARIABLE_NAME:foo}`, which evaluates to `${VARIABLE_NAME}` if
> it's set, or `foo` otherwise).

```
sound volume = 11 # This one is 1 louder

playlist metal {
   files = '''
	/multi/line/strings/are/supported.mp3
	/anything/inside/these/are/stored/verbatim.mp3
   '''
}

playlist chiptune {
   files = """
	/if/it/starts/with/single/quotes/it/ends/with/single/quotes.mod
	/but/it/can/use/double/quotes.s3m
   """
}
```

Some examples can be found in `lwan.conf` and `techempower.conf`.

#### Value types

| Type   | Description |
|--------|-------------|
| `str`  | Any kind of free-form text, usually application specific |
| `int`  | Integer number. Range is application specific |
| `time` | Time interval.  See table below for units |
| `bool` | Boolean value. See table below for valid values |

#### Time Intervals

Time fields can be specified using multipliers. Multiple can be specified, they're
just added together; for instance, "1M 1w" specifies "1 month and 1 week"
(37 days).  The following table lists all known multipliers:

| Multiplier | Description |
|------------|-------------|
| `s`        | Seconds |
| `m`        | Minutes |
| `h`        | Hours |
| `d`        | Days |
| `w`        | 7-day Weeks |
| `M`        | 30-day Months |
| `y`        | 365-day Years |

> :bulb: **Note:** A number with a multiplier not in this table is ignored; a
> warning is issued while reading the configuration file.  No spaces must
> exist between the number and its multiplier.

#### Boolean Values

| True Values | False Values |
|-------------|--------------|
| Any integer number different than 0 | 0 |
| `on` | `off` |
| `true` | `false` |
| `yes` | `no` |

### Global Settings

It's generally a good idea to let Lwan decide the best settings for your
environment.  However, not every environment is the same, and not all uses
can be decided automatically, so some configuration options are provided.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `keep_alive_timeout` | `time`  | `15` | Timeout to keep a connection alive |
| `quiet` | `bool` | `false` | Set to true to not print any debugging messages. Only effective in release builds. |
| `expires` | `time` | `1M 1w` | Value of the "Expires" header. Default is 1 month and 1 week |
| `threads` | `int` | `0` | Number of I/O threads. Default (0) is the number of online CPUs |
| `proxy_protocol` | `bool` | `false` | Enables the [PROXY protocol](https://www.haproxy.com/blog/haproxy/proxy-protocol/). Versions 1 and 2 are supported. Only enable this setting if using Lwan behind a proxy, and the proxy supports this protocol; otherwise, this allows anybody to spoof origin IP addresses |
| `max_post_data_size` | `int` | `40960` | Sets the maximum number of data size for POST requests, in bytes |
| `max_put_data_size` | `int` | `40960` | Sets the maximum number of data size for PUT requests, in bytes |
| `allow_temp_files` | `str` | `""` | Use temporary files; set to `post` for POST requests, `put` for PUT requests, or `all` (equivalent to setting to `post put`) for both.|
| `error_template` | `str` | Default error template | Template for error codes. See variables below. |
| `use_dynamic_buffer` | `bool` | `false` | **Experimental:** use a dynamically-allocated buffer for requests. |

#### Variables for `error_template`

| Variable | Type | Description |
|----------|------|-------------|
| `short_message` | `str` | Short error message (e.g. `Not found`) |
| `long_message` | `str` | Long error message (e.g. `The requested resource could not be found on this server`) |

### Straitjacket

Lwan can drop its privileges to a user in the system, and limit its
filesystem view with a chroot.  While not bulletproof, this provides a
first layer of security in the case there's a bug in Lwan.

In order to use this feature, declare a `straitjacket` section, and set
some options.  This requires Lwan to be executed as `root`.

Although this section can be written anywhere in the file (as long as
it is a top level declaration), if any directories are open, due to
e.g.  instantiating the `serve_files` module, Lwan will refuse to
start.  (This check is only performed on Linux as a safeguard for
malconfiguration.)

> :magic_wand: **Tip:** Declare a Straitjacket right before a `site` section
> in such a way that configuration files and private data (e.g. TLS keys)
> are out of reach of the server after initialization has taken place.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `user` | `str`  | `NULL` | Drop privileges to this user name |
| `chroot` | `str` | `NULL` | Path to `chroot()` |
| `drop_capabilities` | `bool` | `true` | Drop all capabilities with capset(2) (under Linux), or pledge(2) (under OpenBSD). |

### Headers

If there's a need to specify custom headers for each response, one can declare
a `headers` section in the global scope.  The order which this section appears
isn't important.

For example, this declaration:

```
headers {
	Server = Apache/1.0.0 or nginx/1.0.0 (at your option)
	Some-Custom-Header = ${WITH_THIS_ENVIRONMENT_VARIABLE}
}
```

Will both override the `Server` header (`Server: lwan` won't be sent), and set
`Some-Custom-Header` with the value obtained from the environment variable
`$WITH_THIS_ENVIRONMENT_VARIABLE`.

Some headers can't be overridden, as that would cause issues when sending their
actual values while servicing requests.  These include but is not limited to:

  - `Date`
  - `Expires`
  - `WWW-Authenticate`
  - `Connection`
  - `Content-Type`
  - `Transfer-Encoding`
  - All `Access-Control-Allow-` headers

> :bulb: **Note:** Header names are also case-insensitive (and case-preserving).  Overriding
> `SeRVeR` will override the `Server` header, but send it the way it was
> written in the configuration file.

### Listeners

Only two listeners are supported per Lwan process: the HTTP listener (`listener`
section), and the HTTPS listener (`tls_listener` section).  Only one listener
of each type is allowed.

> :warning: **Warning:** TLS support is experimental.  Although it is stable
> during initial testing, your mileage may vary. Only TLSv1.2 is supported
> at this point, but TLSv1.3 is planned.

> :bulb: **Note:** TLS support requires :penguin: Linux with the `tls.ko`
> module built-in or loaded.  Support for other operating systems may be
> added in the future.  FreeBSD seems possible, other operating systems
> do not seem to offer similar feature.  For unsupported operating systems,
> using a TLS terminator proxy such as [Hitch](https://hitch-tls.org/) is a good
> option.

For both `listener` and `tls_listener` sections, the only parameter is the
the interface address and port to listen on.  The listener syntax is
`${ADDRESS}:${PORT}`, where `${ADDRESS}` can either be `*` (binding to all
interfaces), an IPv6 address (if surrounded by square brackets), an IPv4
address, or a hostname.  For instance, `listener localhost:9876` would
listen only in the `lo` interface, port `9876`.

While a `listener` section takes no keys, a `tls_listener` section requires
two: `cert` and `key` (each pointing, respectively, to the location on disk
where the TLS certificate and private key files are located) and takes an
optional boolean `hsts` key, which controls if `Strict-Transport-Security`
headers will be sent on HTTPS responses.

> :magic_wand: **Tip:** To generate these keys for testing purposes, the
> OpenSSL command-line tool can be used like the following:
> `openssl req -nodes -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 7`

> :bulb: **Note:** It's recommended that a [Straitjacket](#Straitjacket) with a `chroot` option is declared
> right after a `tls_listener` section, in such a way that the paths to the
> certificate and key are out of reach from that point on.

If systemd socket activation is used, `systemd` can be specified as a
parameter.  (If multiple listeners from systemd are specified,
`systemd:FileDescriptorName` can be specified, where `FileDescriptorName`
follows the [conventions set in the `systemd.socket` documentation](https://www.freedesktop.org/software/systemd/man/systemd.socket.html).)

Examples:

```
listener *:8080		# Listen on all interfaces, port 8080, HTTP

tls_listener *:8081 {	# Listen on all interfaces, port 8081, HTTPS
	cert = /path/to/cert.pem
	key = /path/to/key.pem
}

# Use named systemd socket activation for HTTP listener
listener systemd:my-service-http.socket

# Use named systemd socket activation for HTTPS listener
tls_listener systemd:my-service-https.socket {
	...
}
```

### Site

A `site` section groups instances of modules and handlers that will respond to
requests to a given URL prefix.

#### Routing URLs Using Modules or Handlers

In order to route URLs, Lwan matches the largest common prefix from the request
URI with a set of prefixes specified in the listener section.  How a request to
a particular prefix will be handled depends on which handler or module has been
declared in the listener section.  Handlers and modules are similar internally;
handlers are merely functions and hold no state, and modules holds state (named
instance).  Multiple instances of a module can appear in a listener section.

There is no special syntax to attach a prefix to a handler or module; all the
configuration parser rules apply here.  Use `${NAME} ${PREFIX}` to link the
`${PREFIX}` prefix path to either a handler named `${NAME}` (if `${NAME}`
begins with `&`, as with C's "address of" operator), or a module named
`${NAME}`.  Empty sections can be used here.

Each module will have its specific set of options, and they're listed in the
next sections.  In addition to configuration options, a special `authorization`
section can be present in the declaration of a module instance.  Handlers do
not take any configuration options, but may include the `authorization`
section.

> :magic_wand: **Tip:** Executing Lwan with the `--help` command-line
> argument will show a list of built-in modules and handlers.

The following is some basic documentation for the modules shipped with Lwan.

#### File Serving

The `serve_files` module will serve static files, and automatically create
directory indices or serve pre-compressed files.  It'll generally try its
best to serve files in the fastest way possible according to some heuristics.


| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `path`                     | `str`  | `NULL`       | Path to a directory containing files to be served |
| `index_path`               | `str`  | `index.html` | File name to serve as an index for a directory |
| `serve_precompressed_path` | `bool` | `true`       | If $FILE.gz exists, is smaller and newer than $FILE, and the client accepts `gzip` encoding, transfer it |
| `auto_index`               | `bool` | `true`       | Generate a directory list automatically if no `index_path` file present.  Otherwise, yields 404 |
| `auto_index_readme`        | `bool` | `true`       | Includes the contents of README files as part of the automatically generated directory index |
| `directory_list_template`  | `str`  | `NULL`       | Path to a Mustache template for the directory list; by default, use an internal template |
| `read_ahead`               | `int`  | `131702`     | Maximum amount of bytes to read ahead when caching open files.  A value of `0` disables readahead.  Readahead is performed by a low priority thread to not block the I/O threads while file extents are being read from the filesystem. |
| `cache_for`                | `time` | `5s`         | Time to keep file metadata (size, compressed contents, open file descriptor, etc.) in cache |

> :bulb: **Note:** Files smaller than 16KiB will be compressed in RAM for
> the duration specified in the `cache_for` setting.  Lwan will always try
> to compress with deflate, and will optionally compress with Brotli and
> zstd (if Lwan has been built with proper support).
>
> In cases where compression wouldn't be worth the effort (e.g. adding the
> `Content-Encoding` header would result in a larger response than sending
> the uncompressed file, usually the case for very small files), Lwan won't
> spend time compressing a file.
>
> For files larger than 16KiB, Lwan will not attempt to compress them.  In
> future versions, it might do this and send responses using
> chunked-encoding while the file is being compressed (up to a certain
> limit, of course), but for now, only precompressed files (see
> `serve_precompressed_path` setting in the table above) are considered.
>
> For all cases, Lwan might try using the gzipped version if that's found in
> the filesystem and the client requested this encoding.

##### Variables for `directory_list_template`

| Variable | Type | Description |
|----------|------|-------------|
| `rel_path` | `str` | Path relative to the root directory real path |
| `readme`   | `str` | Contents of first readme file found (`readme`, `readme.txt`, `read.me`, `README.TXT`, `README`) |
| `file_list` | iterator | Iterates on file list |
| `file_list.zebra_class` | `str` | `odd` for odd items, or `even` or even items |
| `file_list.icon` | `str` | Path to the icon for the file type |
| `file_list.name` | `str` | File name (escaped) |
| `file_list.type` | `str` | File type (directory or regular file) |
| `file_list.size` | `int` | File size |
| `file_list.unit` | `str` | Unit for `file_size` |

#### Lua

The `lua` module will allow requests to be serviced by scripts written in
the [Lua](https://www.lua.org/) programming language.  Although the
functionality provided by this module is quite spartan, it's able to run
frameworks such as [Sailor](https://github.com/lpereira/sailor-hello-lwan).

Scripts can be served from files or embedded in the configuration file, and
the results of loading them, the standard Lua modules, and (optionally, if
using LuaJIT) optimizing the code will be cached for a while.

> :bulb: **Note:** Lua scripts can't use global variables, as they may be not
> only serviced by different threads, but the state will be available only
> for the amount of time specified in the `cache_period` configuration
> option.  This is because each I/O thread in Lwan will create an instance
> of a Lua VM (i.e.  one `lua_State` struct for every I/O thread), and each
> Lwan coroutine will spawn a Lua thread (with `lua_newthread()`) per
> request.

There's no need to have one instance of the Lua module for each endpoint; a
single script, embedded in the configuration file or otherwise, can service
many different endpoints.  Scripts are supposed to implement functions with
the following signature: `handle_${METHOD}_${ENDPOINT}(req)`, where
`${METHOD}` can be a HTTP method (i.e.  `get`, `post`, `head`, etc.), and
`${ENDPOINT}` is the desired endpoint to be handled by that function.

> :magic_wand: **Tip:** Use the `root` endpoint for a catchall. For example,
> the handler function `handle_get_root()` will be called if no other handler
> could be found for that request.  If no catchall is specified, the server
> will return a `404 Not Found` error.

The `req` parameter points to a metatable that contains methods to obtain
information from the request, or to set the response, as seen below:

   - `req:query_param(param)` returns the query parameter (from the query string) with the key `param`, or `nil` if not found
   - `req:post_param(param)` returns the post parameter (only for `${POST}` handlers) with the key `param`, or `nil` if not found
   - `req:set_response(str)` sets the response to the string `str`
   - `req:say(str)` sends a response chunk (using chunked encoding in HTTP)
   - `req:send_event(event, str)` sends an event (using server-sent events)
   - `req:cookie(param)` returns the cookie named `param`, or `nil` is not found
   - `req:set_headers(tbl)` sets the response headers from the table `tbl`; a header may be specified multiple times by using a table, rather than a string, in the table value (`{'foo'={'bar', 'baz'}}`); must be called before sending any response with `say()` or `send_event()`
   - `req:header(name)` obtains the header from the request with the given name or `nil` if not found
   - `req:sleep(ms)` pauses the current handler for the specified amount of milliseconds
   - `req:ws_upgrade()` returns `1` if the connection could be upgraded to a WebSocket; `0` otherwise
   - `req:ws_write_text(str)` sends `str` through the WebSocket-upgraded connection as text frame
   - `req:ws_write_binary(str)` sends `str` through the WebSocket-upgraded connection as binary frame
   - `req:ws_write(str)` sends `str` through the WebSocket-upgraded connection as text or binary frame, depending on content containing only ASCII characters or not
   - `req:ws_read()` returns a string with the contents of the last WebSocket frame, or a number indicating an status (ENOTCONN/107 on Linux if it has been disconnected; EAGAIN/11 on Linux if nothing was available; ENOMSG/42 on Linux otherwise).  The return value here might change in the future for something more Lua-like.
   - `req:remote_address()` returns a string with the remote IP address.
   - `req:path()` returns a string with the request path.
   - `req:query_string()` returns a string with the query string (empty string if no query string present).
   - `req:body()` returns the request body (POST/PUT requests).
   - `req:request_id()` returns a string containing the request ID.
   - `req:request_date()` returns the date as it'll be written in the `Date` response header.
   - `req:is_https()` returns `true` if this request is serviced through HTTPS, `false` otherwise.
   - `req:host()` returns the value of the `Host` header if present, otherwise `nil`.

Handler functions may return either `nil` (in which case, a `200 OK` response
is generated), or a number matching an HTTP status code.  Attempting to return
an invalid HTTP status code or anything other than a number or `nil` will result
in a `500 Internal Server Error` response being thrown.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `default_type` | `str` | `text/plain` | Default MIME-Type for responses |
| `script_file` | `str` | `NULL` | Path to Lua script|
| `cache_period` | `time` | `15s` | Time to keep Lua state loaded in memory |
| `script` | `str` | `NULL` | Inline lua script |

#### Rewrite

The `rewrite` module will match
[patterns](https://man.openbsd.org/patterns.7) in URLs and give the option
to either redirect to another URL, or rewrite the request in a way that Lwan
will handle the request as if it were made in that way originally.

> :information_source: **Info:** Forked from Lua 5.3.1, the regular expresion
> engine may not be as feature-packed as most general-purpose engines, but
> has been chosen specifically because it is a [deterministic finite
> automaton](https://en.wikipedia.org/wiki/Deterministic_finite_automaton)
> in an attempt to make some kinds of [denial of service
> attacks](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
> impossible.

The new URL can be specified using a simple text substitution syntax, or use Lua scripts.

> :magic_wand: **Tip:** Lua scripts will contain the same metamethods
> available in the `req` metatable provided by the Lua module, so it can be
> quite powerful.

Each instance of the rewrite module will require a `pattern` and the action
to execute when such pattern is matched.  Patterns are evaluated in the
order they appear in the configuration file, and are specified using nested
sections in the configuration file.  For instance, consider the following
example, where two patterns are specified:

```
rewrite /some/base/endpoint {
    pattern posts/(%d+) {
        # Matches /some/base/endpointposts/2600 and /some/base/endpoint/posts/2600
        rewrite_as = /cms/view-post?id=%1
    }
    pattern imgur/(%a+)/(%g+) {
        # Matches /some/base/endpointimgur/gif/mpT94Ld and /some/base/endpoint/imgur/gif/mpT94Ld
        redirect_to = https://i.imgur.com/%2.%1
    }
}
```

This example defines two patterns, one providing a nicer URL that's hidden
from the user, and another providing a different way to obtain a direct link
to an image hosted on a popular image hosting service (i.e.  requesting
`/some/base/endpoint/imgur/mp4/4kOZNYX` will redirect directly to a resource
in the Imgur service).

The value of `rewrite_as` or `redirect_to` can be Lua scripts as well; in
which case, the option `expand_with_lua` must be set to `true`, and, instead
of using the simple text substitution syntax as the example above, a
function named `handle_rewrite(req, captures)` has to be defined instead.
The `req` parameter is documented in the Lua module section; the `captures`
parameter is a table containing all the captures, in order (i.e. ``captures[2]``
is equivalent to ``%2`` in the simple text substitition syntax).  This function
returns the new URL to redirect to.

This module has no options by itself.  Options are specified in each and
every pattern.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `rewrite_as` | `str` | `NULL` | Rewrite the URL following this pattern |
| `redirect_to` | `str` | `NULL` | Redirect to a new URL following this pattern |
| `expand_with_lua` | `bool` | `false` | Use Lua scripts to redirect to or rewrite a request |

`redirect_to` and `rewrite_as` options are mutually exclusive, and one of
them must be specified at least.

It's also possible to specify conditions to trigger a rewrite.  To specify one,
open a `condition` block, specify the condition type, and then the parameters
for that condition to be evaluated:

|Condition          |Can use subst. syntax|Section required|Parameters|Description|
|-------------------|---------------------|----------------|----------|-----------|
|`cookie`           | Yes | Yes | A single `key` = `value`| Checks if request has cookie `key` has value `value` |
|`query`            | Yes | Yes | A single `key` = `value`| Checks if request has query variable `key` has value `value` |
|`post`             | Yes | Yes | A single `key` = `value`| Checks if request has post data `key` has value `value` |
|`header`           | Yes | Yes | A single `key` = `value`| Checks if request header `key` has value `value` |
|`environment`      | Yes | Yes | A single `key` = `value`| Checks if environment variable `key` has value `value` |
|`stat`             | Yes | Yes | `path`, `is_dir`, `is_file` | Checks if `path` exists in the filesystem, and optionally checks if `is_dir` or `is_file` |
|`encoding`         | No  | Yes | `deflate`, `gzip`, `brotli`, `zstd`, `none` | Checks if client accepts responses in a determined encoding (e.g. `deflate = yes` for Deflate encoding) |
|`proxied`          | No  | No  | Boolean | Checks if request has been proxied through PROXY protocol |
|`http_1.0`         | No  | No  | Boolean | Checks if request is made with a HTTP/1.0 client |
|`is_https`         | No  | No  | Boolean | Checks if request is made through HTTPS |
|`has_query_string` | No  | No  | Boolean | Checks if request has a query string (even if empty) |
|`method`           | No  | No  | Method name | Checks if HTTP method is the one specified |
|`lua`              | No  | No  | String | Runs Lua function `matches(req)` inside String and checks if it returns `true` or `false` |
|`backref`          | No  | Yes | A single `backref index` = `value` | Checks if the backref number matches the provided value |

*Can use subst. syntax* refers to the ability to reference the matched
pattern using the same substitution syntax used for the `rewrite as` or
`redirect to` actions.  For instance, `condition cookie { some-cookie-name =
foo-%1-bar }` will substitute `%1` with the first match from the pattern
this condition is related to.

> :bulb: **Note:** Conditions that do not require a section have to be written
> as a key; for instance, `condition has_query_string = yes`.

For example, if one wants to send `site-dark-mode.css` if there is a
`style` cookie with the value `dark`, and send `site-light-mode.css`
otherwise, one can write:

```
pattern site.css {
   rewrite as = /site-dark-mode.css
   condition cookie { style = dark }
}
pattern site.css {
   rewrite as = /site-light-mode.css
}
```

Another example: if one wants to send pre-compressed files
if they do exist in the filesystem and the user requested them:

```
pattern (%g+) {
   condition encoding { brotli = yes }
   condition stat { path = %1.brotli }
   rewrite as = %1.brotli
}
pattern (%g+) {
   condition encoding { gzip = yes }
   condition stat { path = %1.gzip }
   rewrite as = %1.gzip
}
pattern (%g+) {
   condition encoding { zstd = yes }
   condition stat { path = %1.zstd }
   rewrite as = %1.zstd
}
pattern (%g+) {
   condition encoding { deflate = yes }
   condition stat { path = %1.deflate }
   rewrite as = %1.deflate
}
```

> :bulb: **Note:** In general, this is not necessary, as the file serving
> module will do this automatically and pick the smallest file available for
> the requested encoding, but this shows it's possible to have a similar
> feature by configuration alone.

#### Redirect

The `redirect` module will, as it says in the tin, generate a `301
Moved permanently` (by default; the code can be changed, see below)
response, according to the options specified in its configuration.
Generally, the `rewrite` module should be used instead as it packs more
features; however, this module serves also as an example of how to
write Lwan modules (less than 100 lines of code).

If the `to` option is not specified, it always generates a `500
Internal Server Error` response.  Specifying an invalid HTTP code, or a
code that Lwan doesn't know about (see `enum lwan_http_status`), will
produce a `301 Moved Permanently` response.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `to` | `str` | `NULL` | The location to redirect to |
| `code` | `int` | `301` | The HTTP code to perform a redirect |

#### Response

The `response` module will generate an artificial response of any HTTP code.
In addition to also serving as an example of how to write a Lwan module,
it can be used to carve out voids from other modules (e.g. generating a
`405 Not Allowed` response for files in `/.git`, if `/` is served with
the `serve_files` module).

If the supplied `code` falls outside the response codes known by Lwan,
a `404 Not Found` error will be sent instead.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `code` | `int` | `999` | A HTTP response code |

#### FastCGI

The `fastcgi` module proxies requests between the HTTP client connecting to
Lwan and a [FastCGI](https://en.wikipedia.org/wiki/FastCGI) server
accessible by Lwan.  This is useful, for instance, to serve pages from a
scripting language such as PHP.

> :bulb: **Note:** This is a preliminary version of this module, and
> as such, it's not well optimized, some features are missing, and
> some values provided to the environment are hardcoded.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `address` | `str` |  | Address to connect to. Can be a file path (for Unix Domain Sockets), IPv4 address (`aaa.bbb.ccc.ddd:port`), or IPv6 address (`[...]:port`). |
| `script_path` | `str` |  | Location where the CGI scripts are located. |
| `default_index` | `str` | `index.php` | Default script to execute if unspecified in the request URI. |

### Authorization Section

Authorization sections can be declared in any module instance or handler,
and provides a way to authorize the fulfillment of that request through
the standard HTTP authorization mechanism.  In order to require authorization
to access a certain module instance or handler, declare an `authorization`
section with a `basic` parameter, and set one of its options.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `realm` | `str` | `Lwan` | Realm for authorization. This is usually shown in the user/password UI in browsers |
| `password_file` | `str` | `NULL` | Path for a file containing username and passwords (in clear text).  The file format is the same as the configuration file format used by Lwan |

> :warning: **Warning:** Not only passwords are stored in clear text in a file
> that should be accessible by the server, they'll be kept in memory for a few
> seconds.  Avoid using this feature if possible.

Hacking
-------

Please read this section (and follow it) if you're planning on contributing
to Lwan.  There's nothing unexpected here; this mostly follows the rules and
expectations of many other FOSS projects, but every one expects things a
little bit different from one another.

### Coding Style

Lwan tries to follow a consistent coding style throughout the project.  If you're
considering contributing a patch to the project, please respect this style by trying
to match the style of the surrounding code.  In general:

 - `global_variables_are_named_like_this`, even though they tend to be rare and should be marked as `static` (with rare exceptions)
 - Local variables are usually shorter, e.g. `local_var`, `i`, `conn`
 - Struct names are often as short as they're descriptive.  `typedef` for structs are rarely used in Lwan
 - Header files should use `#pragma once` instead of the usual include guard hackery
 - Functions that are used between .c files but are not APIs to be exposed to liblwan should have their prototype added to `lwan-private.h`
 - Functions should be short and sweet.  Exceptions may apply
 - Public functions should be prefixed with `lwan_`
 - Public types should be prefixed with `lwan_`
 - Private functions must be static, and can be named without the `lwan_` prefix
 - Code is indented with 4 spaces; don't use tabs
 - There's a suggested line break at column 80, but it's not enforced
 - `/* Old C-style comments are preferred */`
 - `clang-format` can be used to format the source code in an acceptable way; a `.clang-format` file is provided

### Tests

If modifying well-tested areas of the code (e.g. the event loop, HTTP parser,
etc.), please add a new integration test and make sure that, before you send a
pull request, all tests (including the new ones you've sent) are working.
Tests can be added by modifying `src/scripts/testsuite.py`, and executed by
either invoking that script directly from the source root, or executing the
`testsuite` build target.

Some tests will only work on Linux, and won't be executed on other platforms.

### Fuzz-testing

Lwan is automatically fuzz-tested by
[OSS-Fuzz](https://github.com/google/oss-fuzz/).  To fuzz-test locally,
though, one can [follow the instructions to test
locally](https://github.com/google/oss-fuzz/blob/master/docs/new_project_guide.md#testing-locally).

Currently, there are fuzzing drivers for the request parsing code, the
configuration file parser, the template parser, and the Lua string pattern
matching library used in the rewrite module.

Adding new fuzzers is trivial:

- Fuzzers are implemented in C++ and the sources are placed in
  `src/bin/fuzz`.
- Fuzzers should be named `${FUZZER_NAME}_fuzzer.cc`.  Look at the OSS-Fuzz
  documentation and other fuzzers on information about how to write these.
- These files are not compiled by the Lwan build system, but rather by the
  build scripts used by OSS-Fuzz.  To test your fuzzer, please follow the
  instructions to test locally, which will build the fuzzer in the
  environment they'll be executed in.
- A fuzzing corpus has to be provided in `src/fuzz/corpus`.  Files have to
  be named `corpus-${FUZZER_NAME}-${UNIQUE_ID}`.

### Exporting APIs

The shared object version of `liblwan` on ELF targets (e.g. Linux) will use
a symbol filter script to hide symbols that are considered private to the
library.  Please edit `src/lib/liblwan.sym` to add new symbols that should
be exported to `liblwan.so`.

### Using Git and Pull Requests

Lwan tries to maintain a source history that's as flat as possible, devoid of
merge commits.  This means that pull requests should be rebased on top of the
current master before they can be merged; sometimes this can be done
automatically by the GitHub interface, sometimes they need some manual work to
fix conflicts.  It is appreciated if the contributor fixes these conflicts when
asked.

It is advisable to push your changes to your fork on a branch-per-pull request,
rather than pushing to the `master` branch; the reason is explained below.

Please ensure that Git is configured properly with your name (it doesn't really
matter if it is your legal name or a nickname, but it should be enough to credit
you) and a valid email address.  There's no need to add `Signed-off-by` lines,
even though it's fine to send commits with them.

If a change is requested in a pull request, you have two choices:

 - *Reply asking for clarification.*  Maybe the intentions were not clear enough,
and whoever asked for changes didn't fully understand what you were trying to
achieve
 - *Fix the issue.*  When fixing issues found in pull requests, *please* use
[interactive rebases](https://git-scm.com/book/en/v2/Git-Tools-Rewriting-History) to
squash or fixup commits; don't add your fixes on top of your tree.  Do not create
another pull request just to accomodate the changes. After rewriting
the history locally, force-push to your PR branch; the PR will update automatically
with your changes.  Rewriting the history of development branches is fine, and
force-pushing them is normal and expected

It is not enforced, but it is recommended to create smaller commits. How
commits are split in Lwan is pretty much arbitrary, so please take a look at
the commit history to get an idea on how the division should be made.  Git
offers a plethora of commands to achieve this result: the already mentioned
interactive rebase, the `-p` option to `git add`, and `git commit --amend`
are good examples.

Commit messages should have one line of summary (~72 chars), followed by an
empty line, followed by paragraphs of 80-char lines explaining the change.  The
paragraphs explaining the changes are usually not necessary if the summary
is good enough.  Try to [write good commit messages](https://chris.beams.io/posts/git-commit/).

### Licensing

Lwan is licensed under the GNU General Public License, version 2, or (at your option),
any later version.  Therefore:

 - Code must be either LGPLv2.1, GPLv2, a permissive "copyfree" license that is compatible
with GPLv2 (e.g. MIT, BSD 3-clause), or public domain code (e.g. CC0)
 - Although the program can be distributed and used as if it were licensed as GPLv3,
its code must be compatible with GPLv2 as well; no new code can be licensed under versions
of GPL newer than 2
 - Likewise, code licensed under licenses compatible with GPLv3 but
incompatible with GPLv2 (e.g.  Apache 2) are not suitable for inclusion in
Lwan
 - Even if the license does not specify that credit should be given (e.g. CC0-licensed code),
please give credit to the original author for that piece of code
 - Contrary to popular belief, it is possible to use a GPL'd piece of code on a server without
having to share the code for your application.  It is only when the binary of that server is
shared that source must be available to whoever has that binary.  Merely accessing a Lwan
server through HTTP does not qualify as having access to the binary program that's running
on the server
 - When in doubt, don't take legal advice from a README file: please consult
a lawyer that understands free software licensing

Portability
-----------

While Lwan was written originally for Linux, it has been ported to BSD
systems as well.  The build system will detect the supported features
and build support library functions as appropriate.

For instance, [epoll](https://en.wikipedia.org/wiki/Epoll) has been
implemented on top of [kqueue](https://en.wikipedia.org/wiki/Kqueue), and
Linux-only syscalls and GNU extensions have been implemented for the
supported systems.  [This blog post](https://tia.mat.br/posts/2018/06/28/include_next_and_portability.html)
explains the details and how `#include_next` is used.

Performance
-----------

It can achieve good performance, yielding about **320000 requests/second**
on a Core i7 laptop for requests without disk access, and without pipelining.

When disk I/O is required, for files up to 16KiB, it yields about
**290000 requests/second**; for larger files, this drops to **185000
requests/second**, which isn't too shabby either.

These results, of course, with keep-alive connections, and with weighttp
running on the same machine (and thus using resources that could be used
for the webserver itself).

Without keep-alive, these numbers drop around 6-fold.

IRC Channel
-----------

There is an IRC channel (`#lwan`) on [Libera](https://libera.chat). A
standard IRC client can be used.

Lwan in the wild
----------------

Here's a non-definitive list of third-party stuff that uses Lwan and have
been seen in the wild.  *Help build this list!*

* [This project uses Cython and Lwan](https://www.erp5.com/NXD-Blog.Multicore.Python.HTTP.Server) to make it possible to write handlers in Python.
* [An experimental version of Node.js using Lwan](https://github.com/raadad/node-lwan) as its HTTP server is maintained by [@raadad](https://github.com/raadad).
* The beginnings of a C++11 [web framework](https://github.com/vileda/wfpp) based on Lwan written by [@vileda](https://github.com/vileda).
* A more complete C++14 [web framework](https://github.com/matt-42/silicon) by [@matt-42](https://github.com/matt-42) offers Lwan as one of its backends.
* A [word ladder sample program](https://github.com/sjnam/lwan-sgb-ladders) by [@sjnam](https://github.com/sjnam). [Demo](http://tbcoe.ddns.net/sgb/ladders?start=chaos&goal=order).
* A [Shodan search](https://www.shodan.io/search?query=server%3A+lwan) listing some brave souls that expose Lwan to the public internet.
* This [write-up shows the use of Lwan on a Capture the Flag competition](https://medium.com/feedzaitech/pixels-camp-ctf-challenge-qualifiers-writeup-ac661f4af96a).

Some other distribution channels were made available as well:

* Container images are available from the [GitHub Container Registry](https://ghcr.io/lpereira/lwan).  [More information below](#container-images).
* A `Dockerfile` is maintained by [@jaxgeller](https://github.com/jaxgeller), and is [available from the Docker registry](https://hub.docker.com/r/jaxgeller/lwan/).
* A buildpack for Heroku is maintained by [@bherrera](https://github.com/bherrera), and is [available from its repo](https://github.com/bherrera/heroku-buildpack-lwan).
* Lwan is also available as a package in [Biicode](http://docs.biicode.com/c++/examples/lwan.html).
* It's also available in some GNU/Linux distributions:
    * [Arch Linux](https://aur.archlinux.org/packages/lwan-git/)
    * [Ubuntu](https://launchpad.net/lwan-unofficial)
    * [Alpine Linux](https://pkgs.alpinelinux.org/package/edge/testing/x86_64/lwan)
    * [NixOS](https://nixos.org/nixos/packages.html#lwan)
* It's also available as a package for the [Nanos unikernel](https://github.com/nanovms/nanos).

Lwan has been also used as a benchmark:

* [Raphael Javaux's master thesis](https://github.com/RaphaelJ/master-thesis) cites Lwan in chapter 5 ("Performance Analysis").
* Lwan is used as a benchmark by the [PyParallel](http://pyparallel.org/) [author](https://www.reddit.com/r/programming/comments/3jhv80/pyparallel_an_experimental_proofofconcept_fork_of/cur4tut).
* [Kong](https://getkong.org/about/benchmark/) uses Lwan as the [backend API](https://gist.github.com/montanaflynn/01376991f0a3ad07059c) in its benchmark.
* [TechEmpower Framework benchmarks](https://www.techempower.com/benchmarks/#section=data-r10&hw=peak&test=json) feature Lwan since round 10.
* [KrakenD](http://www.krakend.io) used Lwan for the REST API in all official [benchmarks](http://www.krakend.io/docs/benchmarks/aws/)
* [Effective System Call Aggregation (ESCA)](https://github.com/eecheng87/ESCA) project uses Lwan as one of the benchmarks; they claim that Lwan throughput improved by about 30% with their system call batching approach.

Mentions in academic journals:

* [A dynamic predictive race detector for C/C++ programs (in English, published 2017)](https://link.springer.com/article/10.1007/s11227-017-1996-8) uses Lwan as a "real world example".
* [High-precision Data Race Detection Method for Large Scale Programs (in Chinese, published 2021)](http://www.jos.org.cn/jos/article/abstract/6260) also uses Lwan as one of the case studies.

Mentions in magazines:

* [Linux-Magazin (Germany) mentions Lwan in their December/2021 issue](https://www.linux-magazin.de/ausgaben/2021/12/tooltipps/)

Some talks mentioning Lwan:

* [Talk about Lwan](https://www.youtube.com/watch?v=cttY9FdCzUE) at Polyconf16, given by [@lpereira](https://github.com/lpereira).
* This [talk about Iron](https://michaelsproul.github.io/iron-talk/), a framework for Rust, mentions Lwan as an *insane C thing*.
* [University seminar presentation](https://github.com/cu-data-engineering-s15/syllabus/blob/master/student_lectures/LWAN.pdf) about Lwan.
* This [presentation about Sailor web framework](http://www.slideshare.net/EtieneDalcol/web-development-with-lua-bulgaria-web-summit) mentions Lwan.
* [Performance and Scale @ Istio Service Mesh](https://www.youtube.com/watch?v=G4F5aRFEXnU), presented at KubeCon Europe 2018, mentions (at the 7:30 mark) that Lwan is used on the server side for testing due to its performance and robustness.
* [A multi-core Python HTTP server (much) faster than Go (spoiler: Cython)](https://www.youtube.com/watch?v=mZ9cXOH6NYk) presented at PyConFR 2018 by J.-P. Smets mentions [Nexedi's work](https://www.nexedi.com/NXD-Blog.Multicore.Python.HTTP.Server) on using Lwan as a backend for Python services with Cython.

Not really third-party, but alas:

* The [author's blog](http://tia.mat.br).
* The [project's webpage](http://lwan.ws).

Container Images
----------------

Lwan container images are available at
[ghcr.io/lpereira/lwan](https://ghcr.io/lpereira/lwan).  Container runtimes
like [Docker](https://docker.io) or [Podman](https://podman.io) may be used
to build and run Lwan in a container.

### Pull lwan images from GHCR
Container images are tagged with release version numbers, so a specific version of Lwan can be pulled.

    # latest version
    docker pull ghcr.io/lpereira/lwan:latest
    # pull a specific version
    docker pull ghcr.io/lpereira/lwan:v0.3

### Build images locally
Clone the repository and use `Containerfile` (Dockerfile) to build Lwan with all optional dependencies enabled.

    podman build -t lwan .

### Run your image
The image expects to find static content at `/wwwroot`, so a volume containing your content can be mounted.

    docker run --rm -p 8080:8080 -v ./www:/wwwroot lwan

To bring your own `lwan.conf`, simply mount it at `/lwan.conf`.

    podman run --rm -p 8080:8080 -v ./lwan.conf:/lwan.conf lwan

### Run image with socket activation on a Linux host with Podman

Podman supports [socket activation of containers](https://github.com/containers/podman/blob/main/docs/tutorials/socket_activation.md#socket-activation-of-containers).
This example shows how to run lwan with socket activation and Podman on a Linux host.

Requirements: Podman version 4.5.0 or higher.

1. Create user _test_
   ```
   sudo useradd test
   ```
2. Start a login shell for the user _test_
   ```
   sudo machinectl shell test@
   ```
3. Clone the lwan git repository to _~/lwan_
4. Build the image
   ```
   podman build -t lwan ~/lwan
   ```
5. Create directories
   ```
   mkdir -p ~/.config/containers/systemd
   mkdir -p ~/.config/systemd/user
   ```
6. Create the file _~/lwan.conf_ with the contents
   ```
   listener systemd:my.socket
   site {
       serve_files / {
               path = /web
       }
   }
   ```
7. Create the file _~/.config/systemd/user/my.socket_ with the contents
   ```
   [Socket]
   ListenStream=8080
   ```
8. Create the file _~/.config/containers/systemd/my.container_ with the contents
   ```
   [Unit]
   After=my.socket
   Requires=my.socket

   [Container]
   Network=none
   Image=localhost/lwan
   Volume=/home/test/lwan.conf:/lwan.conf:Z
   Volume=/home/test/web:/web:Z
   ```
   The option `:Z` is needed on SELinux systems.
   As __lwan__ only needs to communicate over the socket-activated socket, it's possible to use `Network=none`. See the article [How to limit container privilege with socket activation](https://www.redhat.com/sysadmin/socket-activation-podman).
9. Create the web directory and an example text file
   ```
   mkdir ~/web
   echo hello > ~/web/file.txt
   ```
10. Reload systemd configuration
    ```
    systemctl --user daemon-reload
    ```
11. Start the socket
    ```
    systemctl --user start my.socket
    ```
12. Download the example text file from the lwan web server
    ```
    $ curl localhost:8080/file.txt
    hello
    ```

Lwan quotes
-----------

These are some of the quotes found in the wild about Lwan.  They're presented
in no particular order.  Contributions are appreciated:

> "I read lwan's source code. Especially, the part of using coroutine was
> very impressive and it was more interesting than a good novel.  Thank you
> for that." --
> [@patagonia](https://twitter.com/hakman314/status/996617563470680064)

> "For the server side, we're using Lwan, which can handle 100k+ reqs/s.
> It's supposed to be super robust and it's working well for us." --
> [@fawadkhaliq](https://twitter.com/fawadkhaliq)

> "Insane C thing" -- [Michael
> Sproul](https://michaelsproul.github.io/iron-talk/)

> "I've never had a chance to thank you for Lwan.  It inspired me a lot to
> develop [Zewo](https://github.com/Zewo/Zero)" --
> [@paulofariarl](https://twitter.com/paulofariarl/status/707926806373003265)

> "Let me say that lwan is a thing of beauty.  I got sucked into reading the
> source code for pure entertainment, it's so good.  *high five*" --
> [@kwilczynski](https://twitter.com/kwilczynski/status/692881117003644929)

> "Nice work with Lwan! I haven't looked _that_ carefully yet but so far I
> like what I saw.  You definitely have the right ideas." --
> [@thinkingfish](https://twitter.com/thinkingfish/status/521574267612196864)

> "Lwan is a work of art. Every time I read through it, I am almost always
> awe-struck." --
> [@neurodrone](https://twitter.com/neurodrone/status/359296080283840513)

> "For Round 10, Lwan has taken the crown" --
> [TechEmpower](https://www.techempower.com/blog/2015/04/21/framework-benchmarks-round-10/)

> "Jeez this is amazing. Just end to end, rock solid engineering. (...) But that sells this work short."
> [kjeetgill](https://news.ycombinator.com/item?id=17548983)

> "I am only a spare time C coder myself and was surprised that I can follow the code. Nice!"
> [cntlzw](https://news.ycombinator.com/item?id=17550319)

> "Impressive all and all, even more for being written in (grokkable!) C. Nice work."
> [tpaschalis](https://news.ycombinator.com/item?id=17550961)

> "LWAN was a complete failure" [dermetfan](http://dermetfan.net/posts/zig-with-c-web-servers.html)

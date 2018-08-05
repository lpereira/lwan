Lwan Web Server
===============

Lwan is a **high-performance** & **scalable** web server for glibc/Linux
platforms.

The [project web site](https://lwan.ws/) contains more details.

Build status
------------

| OS      | Arch   | Release | Debug | Static Analysis | Tests |
|---------|--------|---------|-------|-----------------|------------|
| Linux   | x86_64 | ![release](https://shield.lwan.ws/img/gycKbr/release "Release")  | ![debug](https://shield.lwan.ws/img/gycKbr/debug "Debug")     | ![static-analysis](https://shield.lwan.ws/img/gycKbr/clang-analyze "Static Analysis") ![coverity](https://scan.coverity.com/projects/375/badge.svg) [Report history](https://buildbot.lwan.ws/sa/) | ![tests](https://shield.lwan.ws/img/gycKbr/unit-tests "Test")          |
| Linux   | armv7  | ![release-arm](https://shield.lwan.ws/img/gycKbr/release-arm "Release")  | ![debug-arm](https://shield.lwan.ws/img/gycKbr/debug-arm "Debug")     |        |           |
| FreeBSD | x86_64 | ![freebsd-release](https://shield.lwan.ws/img/gycKbr/release-freebsd "Release FreeBSD") | ![freebsd-debug](https://shield.lwan.ws/img/gycKbr/debug-freebsd "Debug FreeBSD")     |                |           |
| macOS   | x86_64 | ![osx-release](https://shield.lwan.ws/img/gycKbr/release-sierra "Release macOS")       | ![osx-debug](https://shield.lwan.ws/img/gycKbr/debug-sierra "Debug macOS")     |               |          |

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
 - Alternative memory allocators can be used by passing `-DUSE_ALTERNATIVE_MALLOC=ON` to CMake:
    - [TCMalloc](https://github.com/gperftools/gperftools)
    - [jemalloc](http://jemalloc.net/)
 - To run test suite:
    - [Python](https://www.python.org/) (2.6+) with Requests
    - [Lua 5.1](http://www.lua.org)
 - To run benchmark:
    - Special version of [Weighttp](https://github.com/lpereira/weighttp)
    - [Matplotlib](https://github.com/matplotlib/matplotlib)
 - To build TechEmpower benchmark suite:
    - Client libraries for either [MySQL](https://dev.mysql.com) or [MariaDB](https://mariadb.org)
    - [SQLite 3](http://sqlite.org)


### Common operating system package names

#### Minimum to build
 - ArchLinux: `pacman -S cmake zlib`
 - FreeBSD: `pkg install cmake pkgconf`
 - Ubuntu 14+: `apt-get update && apt-get install git cmake zlib1g-dev pkg-config`

#### Build all examples
 - ArchLinux: `pacman -S cmake zlib sqlite luajit libmariadbclient gperftools valgrind`
 - FreeBSD: `pkg install cmake pkgconf sqlite3 lua51`
 - Ubuntu 14+: `apt-get update && apt-get install git cmake zlib1g-dev pkg-config lua5.1-dev libsqlite3-dev libmysqlclient-dev`

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

If you'd like to enable optimiations but still use a debugger, use this instead:

    ~/lwan/build$ cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo

To disable optimizations and build a more debugging-friendly version:

    ~/lwan/build$ cmake .. -DCMAKE_BUILD_TYPE=Debug

#### Build Lwan

    ~/lwan/build$ make

This will generate a few binaries:

 - `src/bin/lwan/lwan`: The main Lwan executable. May be executed with `--help` for guidance.
 - `src/bin/testrunner/testrunner`: Contains code to execute the test suite.
 - `src/samples/freegeoip/freegeoip`: FreeGeoIP sample implementation. Requires SQLite.
 - `src/samples/techempower/techempower`: Code for the Techempower Web Framework benchmark. Requires SQLite and MySQL libraries.
 - `src/bin/tools/mimegen`: Builds the extension-MIME type table. Used during build process.
 - `src/bin/tools/bin2hex`: Generates a C file from a binary file, suitable for use with #include.

#### Remarks

Passing `-DCMAKE_BUILD_TYPE=Release` will enable some compiler
optimizations (such as [LTO](http://gcc.gnu.org/wiki/LinkTimeOptimization))
and tune the code for current architecture. *Please use this version
when benchmarking*, as the default is the Debug build, which not only
logs all requests to the standard output, but does so while holding a
mutex.

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
supports [TCMalloc](https://github.com/gperftools/gperftools) and
[jemalloc](http://jemalloc.net/) out of the box.  To use either one of them,
pass `-DALTERNATIVE_MALLOC=ON` to the CMake invocation line.

### Tests

    ~/lwan/build$ make teststuite

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
very simple and should be self-explanatory.

Configuration files are loaded from the current directory. If no changes
are made to this file, running Lwan will serve static files located in
the `./wwwroot` directory. Lwan will listen on port 8080 on all interfaces.

Lwan will detect the number of CPUs, will increase the maximum number of
open file descriptors and generally try its best to autodetect reasonable
settings for the environment it's running on.  Many of these settings can
be tweaked in the configuration file, but it's usually a good idea to not
mess with them.

Optionally, the `lwan` binary can be used for one-shot static file serving
without any configuration file. Run it with `--help` for help on that.

Built-in modules
----------------

A list of built-in modules can be obtained by executing Lwan with the `-m`
command-line argument.

### Built-in modules

A list of built-in modules can be obtained by executing Lwan with the `-m`
command-line argument.  The following is some basic documentation for the modules shipped with Lwan.

Note that, for options in configuration files, `this_key` is equivalent to `this key`.

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
| `directory_list_template`  | `str`  | `NULL`       | Path to a Mustache template for the directory list; by default, use an internal template |

#### Lua

The `lua` module will allow requests to be serviced by scripts written in
the [Lua](https://www.lua.org/) programming language.  Although the
functionality provided by this module is quite spartan, it's able to run
frameworks such as [Sailor](https://github.com/lpereira/sailor-hello-lwan).

Scripts can be served from files or embedded in the configuration file, and
the results of loading them, the standard Lua modules, and (optionally, if
using LuaJIT) optimizing the code will be cached for a while.  Each I/O
thread in Lwan will create an instance of a Lua VM (i.e.  one `lua_State`
struct for every I/O thread), and each Lwan coroutine will spawn a Lua
thread (with `lua_newthread()`) per request.  Because of this, Lua scripts
can't use global variables, as they may be not only serviced by different
threads, but the state will be available only for the amount of time
specified in the `cache_period` configuration option.

There's no need to have one instance of the Lua module for each endpoint; a
single script, embeded in the configuration file or otherwise, can service
many different endpoints.  Scripts are supposed to implement functions with
the following signature: `handle_${METHOD}_${ENDPOINT}(req)`, where
`${METHOD}` can be a HTTP method (i.e.  `get`, `post`, `head`, etc.), and
`${ENDPOINT}` is the desired endpoint to be handled by that function.  The
special `${ENDPOINT}` `root` can be specified to act as a catchall.  The
`req` parameter points to a metatable that contains methods to obtain
information from the request, or to set the response, as seen below:

   - `req:query_param(param)` returns the query parameter (from the query string) with the key `param`, or `nil` if not found
   - `req:post_param(param)` returns the post parameter (only for `${POST}` handlers) with the key `param`, or `nil` if not found
   - `req:set_response(str)` sets the response to the string `str`
   - `req:say(str)` sends a response chunk (using chunked encoding in HTTP)
   - `req:send_event(event, str)` sends an event (using server-sent events)
   - `req:cookie(param)` returns the cookie named `param`, or `nil` is not found
   - `req:set_headers(tbl)` sets the response headers from the table `tbl`; a header may be specified multiple times by using a table, rather than a string, in the table value (`{'foo'={'bar', 'baz'}}`); must be called before sending any response with `say()` or `send_event()`
   - `req:sleep(ms)` pauses the current handler for the specified amount of milliseconds

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `default_type` | `str` | `text/plain` | Default MIME-Type for responses |
| `script_file` | `str` | `NULL` | Path to Lua script|
| `cache_period` | `time` | `15s` | Time to keep Lua state loaded in memory |
| `script` | `str` | `NULL` | Inline lua script |

Rewrite
-------

The `rewrite` module will match
[patterns](https://man.openbsd.org/patterns.7) in URLs and give the option
to either redirect to another URL, or rewrite the request in a way that Lwan
will handle the request as if it were made in that way originally.  The
patterns are a special kind of regular expressions, forked from Lua 5.3.1,
that do not contain backreferences and other features that could create
denial-of-service issues in Lwan.  The new URL can be specified using a
simple text substitution syntax, or use Lua scripts; Lua scripts will
contain the same metamethods available in the `req` metatable provided by
the Lua module, so it can be quite powerful.

Each instance of the rewrite module will require a `pattern` and the action
to execute when such pattern is matched.  Patterns are evaluated in the
order they appear in the configuration file, and are specified using nested
sections in the configuration file.  For instance, consider the following
example, where two patterns are specified:

```
rewrite /some/base/endpoint {
    pattern posts/(%d+) {
        rewrite_as = /cms/view-post?id=%1
    }
    pattern imgur/(%a+)/(%g+) {
        redirect_to = https://i.imgur.com/%2.%1
    }
}
```

This example defines two patterns, one providing a nicer URL that's hidden
from the user, and another providing a dufferent way to obtain a direct link
to an image hosted on a popular image hosting service.

The value of `rewrite_as` or `redirect_to` can be Lua scripts as well; in
which case, the option `expand_with_lua` must be set to `true`, and, instead
of using the simple text substitution syntax as the example above, a
function named `handle_rewrite(req, captures)` has to be defined instead.
The `req` parameter is documented in the Lua module section; the `captures`
parameter is a table containing all the captures, in order.  This function
returns the new URL to redirect to.

This module has no options by itself.

Portability
-----------

While Lwan was written originally for Linux, it has been ported to BSD
systems as well.  The build system will detect the supported features
and build support library functions as appropriate.

For instance, [epoll](https://en.wikipedia.org/wiki/Epoll) has been
implemented on top of [kqueue](https://en.wikipedia.org/wiki/Kqueue), and
Linux-only syscalls and GNU extensions have been implemented for the
supported systems.

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

There is an IRC channel (`#lwan`) on [Freenode](http://freenode.net). A
standard IRC client can be used.  A [web IRC gateway](http://webchat.freenode.net?channels=%23lwan&uio=d4)
is also available.

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

Some other distribution channels were made available as well:

* A `Dockerfile` is maintained by [@jaxgeller](https://github.com/jaxgeller), and is [available from the Docker registry](https://hub.docker.com/r/jaxgeller/lwan/).
* A buildpack for Heroku is maintained by [@bherrera](https://github.com/bherrera), and is [available from its repo](https://github.com/bherrera/heroku-buildpack-lwan).
* Lwan is also available as a package in [Biicode](http://docs.biicode.com/c++/examples/lwan.html).
* It's also available in some GNU/Linux distributions:
    * [Arch Linux](https://aur.archlinux.org/packages/lwan-git/)
    * [Ubuntu](https://launchpad.net/lwan-unofficial)
    * [Alpine Linux](https://pkgs.alpinelinux.org/package/edge/testing/x86_64/lwan)
    * [NixOS](https://nixos.org/nixos/packages.html#lwan)

Lwan has been also used as a benchmark:

* [Raphael Javaux's master thesis](https://github.com/RaphaelJ/master-thesis) cites Lwan in chapter 5 ("Performance Analysis").
* Lwan is used as a benchmark by the [PyParallel](http://pyparallel.org/) [author](https://www.reddit.com/r/programming/comments/3jhv80/pyparallel_an_experimental_proofofconcept_fork_of/cur4tut).
* [Kong](https://getkong.org/about/benchmark/) uses Lwan as the [backend API](https://gist.github.com/montanaflynn/01376991f0a3ad07059c) in its benchmark.
* [TechEmpower Framework benchmarks](https://www.techempower.com/benchmarks/#section=data-r10&hw=peak&test=json) feature Lwan since round 10.
* [KrakenD](http://www.krakend.io) used Lwan for the REST API in all official [benchmarks](http://www.krakend.io/docs/benchmarks/aws/)

Mentions in academic journals:

* [A dynamic predictive race detector for C/C++ programs](https://link.springer.com/article/10.1007/s11227-017-1996-8) uses Lwan as a "real world example".

Some talks mentioning Lwan:

* [Talk about Lwan](https://www.youtube.com/watch?v=cttY9FdCzUE) at Polyconf16, given by [@lpereira](https://github.com/lpereira).
* This [talk about Iron](https://michaelsproul.github.io/iron-talk/), a framework for Rust, mentions Lwan as an *insane C thing*.
* [University seminar presentation](https://github.com/cu-data-engineering-s15/syllabus/blob/master/student_lectures/LWAN.pdf) about Lwan.
* This [presentation about Sailor web framework](http://www.slideshare.net/EtieneDalcol/web-development-with-lua-bulgaria-web-summit) mentions Lwan.
* [Performance and Scale @ Istio Service Mesh](https://www.youtube.com/watch?v=G4F5aRFEXnU), at around 7:30min, presented at KubeCon Europe 2018, mentions that Lwan is used on the server side for testing due to its performance and robustness.

Not really third-party, but alas:

* The [author's blog](http://tia.mat.br).
* The [project's webpage](http://lwan.ws).

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

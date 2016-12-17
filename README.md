Lwan Web Server
===============

Lwan is a **high-performance** & **scalable** web server for glibc/Linux
platforms.

In development for almost 4 years, Lwan was until now a personal research
effort that focused mostly on building a **solid infrastructure** for
a lightweight and speedy web server:

  - Low memory footprint (~500KiB for 10k idle connections)
  - Minimal memory allocations & copies
  - Minimal system calls
  - Hand-crafted HTTP request parser
  - Files are served using the most efficient way according to their size
    - No copies between kernel and userland for files larger than 16KiB
    - Smaller files are sent using vectored I/O of memory-mapped buffers
    - Header overhead is considered before compressing small files
  - Mostly wait-free multi-threaded design
  - Diminute code base with roughly 7200 lines of C code

It is now transitioning into a fully working, capable HTTP server. It is
not, however, as feature-packed as other popular web servers. But it is
[free software](http://www.gnu.org/philosophy/free-sw.html), so scratching
your own itches and making Lwan hum the way you want it to is possible.

Features include:

  - Mustache templating engine
    - Used for directory listing & error messages
    - Available for user-built handlers
  - Easy to use API to create web applications or extend the web server
  - Supports rebimboca da parafuseta
  - Test suite written in Python tests the server as a black box
  - No-nonsense configuration file syntax
  - Supports a subset of HTTP/1.0 and HTTP/1.1
  - systemd socket activation
  - IPv6 ready

The [web site](https://lwan.ws/) has more details, including a FAQ about the name of the project and security concerns.

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

Portability
-----------

Although it uses [epoll](https://en.wikipedia.org/wiki/Epoll) and the
Linux variant of sendfile(), it is fairly portable to other event-based
pollers, like [kqueue](https://en.wikipedia.org/wiki/Kqueue).

Porting for FreeBSD and OS X is a work in progress.   It works on
FreeBSD, but the module registry can't find any module and/or handlers
(so it's essentially only serves 404 pages at the moment).  Help to fix
this is appreciated.

Building
--------

Before installing Lwan, ensure all dependencies are installed. All of them are common dependencies found in any GNU/Linux distribution; package names will be different, but it shouldn't be difficult to search using whatever package management tool that's used by your distribution.

### Required dependencies

 - [CMake](https://cmake.org/), at least version 2.8
 - [ZLib](http://zlib.net)

### Optional dependencies

The build system will look for these libraries and enable/link if available.

 - [SQLite 3](http://sqlite.org)
 - [Lua 5.1](http://www.lua.org) or [LuaJIT 2.0](http://luajit.org)
 - Client libraries for either [MySQL](https://dev.mysql.com) or [MariaDB](https://mariadb.org)
 - [TCMalloc](https://github.com/gperftools/gperftools)
 - [jemalloc](http://www.canonware.com/jemalloc/)
 - [Valgrind](http://valgrind.org)
 - To run test suite:
    - [Python](https://www.python.org/) (2.6+) with Requests
    - [Lua 5.1](http://www.lua.org)
 - To run benchmark :
    - Special version of [Weighttp](https://github.com/lpereira/weighttp)
    - [Matplotlib](https://github.com/matplotlib/matplotlib)

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

 - `lwan/lwan`: The main Lwan executable. May be executed with `--help` for guidance.
 - `testrunner/testrunner`: Contains code to execute the test suite.
 - `freegeoip/freegeoip`: FreeGeoIP sample implementation. Requires SQLite.
 - `techempower/techempower`: Code for the Techempower Web Framework benchmark. Requires SQLite and MySQL libraries.
 - `common/mimegen`: Builds the extension-MIME type table. Used during build process.

#### Remarks

It is important to build outside of the tree; in-tree builds *are not supported*.

Passing `-DCMAKE_BUILD_TYPE=Release` will enable some compiler
optimizations (such as [LTO](http://gcc.gnu.org/wiki/LinkTimeOptimization))
and tune the code for current architecture. *Please use this version
when benchmarking*, as the default is the Debug build, which not only
logs all requests to the standard output, but does so while holding a
mutex.

The default build (i.e. not passing `-DCMAKE_BUILD_TYPE=Release`) will build
a version suitable for debugging purposes. This version can be used under
Valgrind, is built with Undefined Behavior Sanitizer, and includes debugging
messages that are stripped in the release version. Debugging messages are
printed for each and every request.

### Tests

    ~/lwan/build$ make teststuite

This will compile `testrunner/testrunner` and execute regression test suite in `tool/testsuite.py`.

### Benchmark

    ~/lwan/build$ make benchmark

This will compile `testrunner/testrunner` and execute benchmark script `tools/benchmark.py`.

Running
-------

Set up the server by editing the provided `lwan.conf`; the format is
very simple and should be self-explanatory.

Configuration files are loaded from the current directory. If no changes
are made to this file, running Lwan will serve static files located in
the `./wwwroot` directory. Lwan will listen on port 8080 on all interfaces.

Lwan will detect the number of CPUs, will increase the maximum number of
open file descriptors and generally try its best to autodetect reasonable
settings for the environment it's running on.

Optionally, the `lwan` binary can be used for one-shot static file serving
without any configuration file. Run it with `--help` for help on that.

IRC Channel
-----------

There is an IRC channel (`#lwan`) on [Freenode](http://freenode.net). A
standard IRC client can be used.  A [web IRC gateway](http://webchat.freenode.net?channels=%23lwan&uio=d4)
is also available.


Lwan in the wild
----------------

Here's a non-definitive list of third-party stuff that uses Lwan and have
been seen in the wild.  *Help build this list!*

* [An experimental version of Node.js using Lwan](https://github.com/raadad/node-lwan) as its HTTP server is maintained by [@raadad](https://github.com/raadad).
* The beginnings of a C++11 [web framework](https://github.com/vileda/wfpp) based on Lwan written by [@vileda](https://github.com/vileda).
* A more complete C++14 [web framework](https://github.com/matt-42/silicon) by [@matt-42](https://github.com/matt-42) offers Lwan as one of its backends.
* A [word ladder sample program](https://github.com/sjnam/lwan-sgb-ladders) by [@sjnam](https://github.com/sjnam). [Demo](http://tbcoe.ddns.net/sgb/ladders?start=chaos&goal=order).
* A [Shodan search](https://www.shodan.io/search?query=server%3A+lwan) listing some brave souls that expose Lwan to the public internet.

Some other distribution channels were made available as well:

* A `Dockerfile` is maintained by [@jaxgeller](https://github.com/jaxgeller), and is [available from the Docker registry](https://hub.docker.com/r/jaxgeller/lwan/).
* A buildpack for Heroku is maintained by [@bherrera](https://github.com/bherrera), and is [available from its repo](https://github.com/bherrera/heroku-buildpack-lwan).
* Lwan is also available as a package in [Biicode](http://docs.biicode.com/c++/examples/lwan.html).
* User packages for [Arch Linux](https://aur.archlinux.org/packages/lwan-git/) and [Ubuntu](https://launchpad.net/lwan-unofficial).

Lwan has been also used as a benchmark:

* [Raphael Javaux's master thesis](https://github.com/RaphaelJ/master-thesis) cites Lwan in chapter 5 ("Performance Analysis").
* Lwan is used as a benchmark by the [PyParallel](http://pyparallel.org/) [author](https://www.reddit.com/r/programming/comments/3jhv80/pyparallel_an_experimental_proofofconcept_fork_of/cur4tut).
* [Kong](https://getkong.org/about/benchmark/) uses Lwan as the [backend API](https://gist.github.com/montanaflynn/01376991f0a3ad07059c) in its benchmark.
* [TechEmpower Framework benchmarks](https://www.techempower.com/benchmarks/#section=data-r10&hw=peak&test=json) feature Lwan since round 10.

Some talks mentioning Lwan:

* [Talk about Lwan](https://www.youtube.com/watch?v=cttY9FdCzUE) at Polyconf16, given by [@lpereira](https://github.com/lpereira).
* This [talk about Iron](https://michaelsproul.github.io/iron-talk/), a framework for Rust, mentions Lwan as an *insane C thing*.
* [University seminar presentation](https://github.com/cu-data-engineering-s15/syllabus/blob/master/student_lectures/LWAN.pdf) about Lwan.
* This [presentation about Sailor web framework](http://www.slideshare.net/EtieneDalcol/web-development-with-lua-bulgaria-web-summit) mentions Lwan.

Not really third-party, but alas:

* The [author's blog](http://tia.mat.br).
* The [project's webpage](http://lwan.ws).

Build status
------------

| Platform | Release | Debug | Static Analysis | Tests |
|----------|---------|-------|-----------------|------------|
| Linux    | ![release](https://shield.lwan.ws/img/gycKbr/release "Release")  | ![debug](https://shield.lwan.ws/img/gycKbr/debug "Debug")     | ![static-analysis](https://shield.lwan.ws/img/gycKbr/clang-analyze "Static Analysis") ![coverity](https://scan.coverity.com/projects/375/badge.svg) [Report history](https://buildbot.lwan.ws/sa/) | ![tests](https://shield.lwan.ws/img/gycKbr/unit-tests "Test")          |
| FreeBSD  | ![freebsd-release](https://shield.lwan.ws/img/gycKbr/release-freebsd "Release FreeBSD") | ![freebsd-debug](https://shield.lwan.ws/img/gycKbr/debug-freebsd "Debug FreeBSD")     |                |           |
| OS X     | ![osx-release](https://shield.lwan.ws/img/gycKbr/release-yosemite "Release OS X")       | ![osx-debug](https://shield.lwan.ws/img/gycKbr/debug-yosemite "Debug OS X")     |               |          |

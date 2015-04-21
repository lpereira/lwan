lwan Web Server
===============

Lwan is a **high-performance** & **scalable** web server for glibc/Linux
platforms.

In development for almost 3 years, Lwan was until now a personal research
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

The [web site](http://lwan.ws) has more details, including a FAQ about the name of the project and security concerns.

Performance
-----------

It can achieve good performance, yielding about **320000 requests/second**
on a Core i7 laptop for requests without disk access.

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
An old version of lwan has been [successfully ported to
FreeBSD](https://github.com/rakuco/lwan/tree/kqueue-port).  Eventually,
some event library such as [libev](http://libev.schmorp.de) or
[libevent](http://libevent.org) will be used to aid in portability.

Building
--------

Before installing Lwan, ensure all dependencies are installed. All of them are common dependencies found in any GNU/Linux distribution; package names will be different, but it shouldn't be difficult to search using whatever package management tool that's used by your distribution.

### Required dependencies

 - [CMake](http://cmake.org), at least version 2.8
 - [Python](http://python.org), at least version 2.6 (3.x is OK)
 - [ZLib](http://zlib.net)

### Optional dependencies

The build system will look for these libraries and enable/link if available.

 - [SQLite 3](http://sqlite.org)
 - [Lua 5.1](http://www.lua.org) or [LuaJIT 2.0](http://luajit.org)
 - Client libraries for either [MySQL](https://dev.mysql.com) or [MariaDB](https://mariadb.org)
 - [TCMalloc](https://code.google.com/p/gperftools/)
 - [jemalloc](http://www.canonware.com/jemalloc)
 - [Valgrind](http://valgrind.org)

### Common distribution package names

 - ArchLinux: `pacman -S cmake python zlib sqlite luajit libmariadbclient gperftools valgrind`
 - Ubuntu 14: `apt-get update && apt-get install git cmake zlib1g-dev pkg-config lua5.1-dev libsqlite3-dev libmysql++-dev`

### Build commands

    ~$ git clone git://github.com/lpereira/lwan
    ~$ cd lwan
    ~/lwan$ mkdir build
    ~/lwan$ cd build
    ~/lwan/build$ cmake .. -DCMAKE_BUILD_TYPE=Release
    ~/lwan/build$ make

It is important to build outside of the tree; in-tree builds *are not supported*.

Passing `-DCMAKE_BUILD_TYPE=Release` will enable some compiler
optimizations, like [LTO](http://gcc.gnu.org/wiki/LinkTimeOptimization)
and tune the code for current architecture. *Please use this version
when benchmarking*, as the default is the Debug build, which not only
logs all requests to the standard output, but does so while holding a
mutex.

The default build (i.e. not passing `-DCMAKE_BUILD_TYPE=Release`) will build
a version suitable for debugging purposes. This version can be used under
Valgrind, is built with Undefined Behavior Sanitizer, and includes debugging
messages that are stripped in the release version. Debugging messages are
printed while holding a mutex, and are printed for each and every request;
so do not use this version for benchmarking purposes.

Running
-------

Set up the server by editing the provided `lwan.conf`; the format is
very simple and should be self-explanatory.

Configuration files are loaded from the current directory. If no changes
are made to this file, running lwan will serve static files located in
the `./wwwroot` directory, and also provide a `Hello, World!` handler (which
serves as an example of how to use some of its internal APIs).

Lwan will listen on port 8080 on all interfaces.

Lwan will detect the number of CPUs, will increase the maximum number of
open file descriptors and generally try its best to autodetect reasonable
settings for the environment it's running on.

Build status
------------

| Release | Debug | Static Analysis | Unit Tests |
|---------|-------|-----------------|------------|
| ![release](http://buildbot.lwan.ws/buildstatusimage?builder=release&number=-1 "Release") | ![debug](http://buildbot.lwan.ws/buildstatusimage?builder=debug&number=-1 "Debug") | ![clang](http://buildbot.lwan.ws/buildstatusimage?builder=clang-analyze&number=-1 "Clang") ![coverity](https://scan.coverity.com/projects/375/badge.svg)| ![tests](http://buildbot.lwan.ws/buildstatusimage?builder=unit-tests&number=-1 "Tests")
| [Waterfall](http://buildbot.lwan.ws/waterfall?show=release) | [Waterfall](http://buildbot.lwan.ws/waterfall?show=debug) | [Waterfall](http://buildbot.lwan.ws/waterfall?show=clang-analyze) - [Reports](http://buildbot.lwan.ws/sa/) | [Waterfall](http://buildbot.lwan.ws/waterfall?show=unit-tests) |


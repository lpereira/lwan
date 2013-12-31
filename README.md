lwan Web Server
===============

Lwan is a **high-performance** & **scalable** web server for glibc/Linux platforms.

In development for about 2 years, Lwan was until now a personal research effort that focused mostly on building a **solid infrastructure** for a lightweight and speedy web server:

  - Low memory footprint (~1.5MiB for 10k idle connections)
  - Minimal memory allocations & copies
  - Minimal system calls
  - Hand-crafted HTTP request parser
  - Files are served using the most efficient way according to their size
    - No copies between k ernel and userland for files larger than 16KiB
    - Smaller files are sent using vectored I/O of memory-mapped buffers
    - Header overhead is considered before compressing small files
  - Mostly wait-free multi-threaded design
  - Diminute code base with roughly 7200 lines of C code

It is now transitioning into a fully working, capable HTTP server. It is not, however, as feature-packed as other popular web servers. But it is **free software**, so scratching your own itches and making LWan hum the way you want it to is possible.

Features include:

  - Mustache templating engine
    - Used for directory listing & error messages
    - Available for user-built handlers
  - Easy to use API to create web applications or extend the web server
  - Supports rebimboba da parafuseta
  - Test suite written in Python tests the server as a black box
  - No-nonsense configuration file syntax
  - Supports a subset of HTTP/1.0 and HTTP/1.1

The [web site](http://lwan.ws) has more details.

Performance
-----------

It can achieve good performance, yielding about **300000 requests/second** on a Core i7 laptop for requests without disk access.

When disk I/O is required, for files up to 16KiB, it yields about **285000 requests/second**; for larger files, this drops to **185000 requests/second**, which isn't too shabby either.

These results, of course, with keep-alive connections, and with weighttp running on the same machine (and thus using resources that could be used for the webserver itself).

Without keep-alive, these numbers drop around 6-fold.

Portability
-----------

Although it uses [epoll](https://en.wikipedia.org/wiki/Epoll) and the Linux variant of sendfile(), it is fairly portable to other event-based pollers, like [kqueue](https://en.wikipedia.org/wiki/Kqueue).  An old version of lwan has been [successfully ported to FreeBSD](https://github.com/rakuco/lwan/tree/kqueue-port).  Eventually, some event library such as [libev](http://libev.schmorp.de) or [libevent](http://libevent.org) will be used to aid in portability.

Work is underway to port it to [OSv](http://osv.io), an operating system designed specifically for virtual machines.

Usage
-----

Although lwan is [Free Software](http://www.gnu.org/philosophy/free-sw.html), released under GNU GPL version 2, keep in mind that it is extensively research-quality software.  It **has not been tested beyond synthetic and simplistic benchmarks**, so it may not work as expected when faced with real life workloads.  If you're looking for a web server, try [Apache](http://apache.org), [Cherokee](http://www.cherokee-project.com) or [Nginx](http://nginx.org).

If even with that warning, you'd like to try lwan, after building it (instructions below), one can set it up by editing the provided `lwan.conf`; the format is very simple and should be self-explanatory. Configuration files are loaded from the current directory. If no changes are made to this file, running lwan will serve static files located on `./wwwroot` directory, and also provide a `Hello, World!` handler (which serves as an example of how to use its internal APIs).  Lwan will listen on port 8080 on all interfaces.


Building
--------

Lwan uses CMake for its build system. To build it, create a build directory, issue `cmake $LWAN_SOURCE_TREE`, and then `make`, as usual.

The CMake script should look for libraries like [TCMalloc](https://code.google.com/p/gperftools/), [jemalloc](http://www.canonware.com/jemalloc), and [Valgrind](http://valgrind.org), and enable/link as appropriate.

Passing `-DCMAKE_BUILD_TYPE=Release` will enable some compiler optimizations, like [LTO](http://gcc.gnu.org/wiki/LinkTimeOptimization) and tune the code for current architecture. Passing `-DCMAKE_BUILD_TYPE=Debug` will generate code suitable to be used under a debugger like [gdb](http://www.gnu.org/software/gdb/) and force debug messages to be printed to the terminal.

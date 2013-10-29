lwan Web Server
===============

Lwan is a **high-performance** & **scalable** web server written in C for glibc/Linux platforms.  It is not designed to be standards compliant; only a small subset of HTTP/1.1 is supported (to enable keep-alive connections).

It can achieve good performance, yielding about **300000 requests/second** on a Core i7 laptop for requests without disk access. When disk I/O is required, for files up to 16KiB, it yields about **285000 requests/second**; for larger files, this drops to **185000 requests/second**, which isn't too shabby either. These results, of course, with keep-alive connections, and with weighttp running on the same machine (and thus using resources that could be used for the webserver itself).  Without keep-alive, these numbers drop around 6-fold.

Portability
-----------

Although it uses [epoll](https://en.wikipedia.org/wiki/Epoll), the Linux variant of sendfile(), it is fairly portable to other event-based pollers, like [kqueue](https://en.wikipedia.org/wiki/Kqueue).  An old version of lwan has been [successfully ported to FreeBSD](https://github.com/rakuco/lwan/tree/kqueue-port).  Eventually, some event library such as [libev](http://libev.schmorp.de) or [libevent](http://libevent.org) will be used to aid in portability.  However, portability is not a current goal for this project.

Goal
----

lwan's goal is to provide a testbed for multithreaded, event-based programs.  It is by no means a substitute for real, standards-compliant, web servers.

Usage
-----

Although lwan is [Free Software](http://www.gnu.org/philosophy/free-sw.html), released under GNU GPL version 2, keep in mind that it is extensively research-quality software.  It **has not been tested beyond synthetic and simplistic benchmarks**, so it may not work as expected when faced with real life workloads.  If you're looking for a web server, try [Apache](http://apache.org), [Cherokee](http://www.cherokee-project.com) or [Nginx](http://nginx.org).

If even with that warning you'd like to try lwan: there is no configuration file.  All settings are made in the `main()` function located in the `main.c` file; you'll need to recompile and restart lwan so that these settings take effect.  Things should be pretty self-explanatory.  Also, `main.c` serves as an example of how you could embed lwan in your program; the embedding API isn't ready yet, so there is no way to integrate main loops.

If no changes are made to the supplied `main.c` file, running lwan will serve static files located on `./files_root` directory.  Lwan will listen on port 8080 on all interfaces.

Building
--------

Lwan uses CMake for its build system. To build it, create a build directory, issue `cmake $LWAN_SOURCE_TREE`, and then `make`, as usual. The CMake script should look for libraries like [TCMalloc](https://code.google.com/p/gperftools/) and [Valgrind](http://valgrind.org), and enable/link as appropriate. Passing `-DCMAKE_BUILD_TYPE=Release` will enable some compiler optimizations, like [LTO](http://gcc.gnu.org/wiki/LinkTimeOptimization) and tune the code for current architecture. Passing `-DCMAKE_BUILD_TYPE=Debug` will generate code suitable to be used under a debugger like [gdb](http://www.gnu.org/software/gdb/).

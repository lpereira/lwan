project(lwan C)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow")

if (${CMAKE_BUILD_TYPE} MATCHES "Rel")
	message(STATUS "Enabling compiler optimizations")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mtune=native -O3 -flto")
endif ()

find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)
find_library(TCMALLOC_LIBRARY NAMES tcmalloc /usr/lib /usr/local/lib)
if (TCMALLOC_LIBRARY)
	message(STATUS "TCMalloc found: ${TCMALLOC_LIBRARY}")
else ()
	message(STATUS "TCMalloc not found, using system malloc")
	set(TCMALLOC_LIBRARY "")
endif()

find_path(VALGRIND_INCLUDE_DIR valgrind.h /usr/include /usr/include/valgrind /usr/local/include /usr/local/include/valgrind)
if (VALGRIND_INCLUDE_DIR)
	message(STATUS "Building with Valgrind support")
	add_definitions("-DUSE_VALGRIND=1")
else ()
	message(STATUS "Valgrind headers not found -- disabling valgrind support")
endif()

include(FindPkgConfig)
pkg_check_modules(SQLITE REQUIRED sqlite3>=3.7.15.2)

add_library(lwan-common STATIC
	lwan.c
	lwan-coro.c
	lwan-dir-watch.c
	lwan-openat.c
	lwan-request.c
	lwan-response.c
	lwan-sendfile.c
	lwan-serve-files.c
	lwan-socket.c
	lwan-tables.c
	lwan-thread.c
	lwan-trie.c
	lwan-status.c
	hash.c
	int-to-str.c
	murmur3.c
	realpathat.c
	strbuf.c
	template.c
)

add_executable(lwan main.c)

target_link_libraries(lwan
	${CMAKE_THREAD_LIBS_INIT}
	${TCMALLOC_LIBRARY}
	${ZLIB_LIBRARIES}
	lwan-common
)

add_executable(freegeoip
	freegeoip.c
	memcache.c
)

target_link_libraries(freegeoip
	${CMAKE_THREAD_LIBS_INIT}
	${TCMALLOC_LIBRARY}
	${ZLIB_LIBRARIES}
	${SQLITE_LIBRARIES}
	lwan-common
)

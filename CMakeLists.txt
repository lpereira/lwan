cmake_minimum_required(VERSION 3.20)
project(lwan C)
set(PROJECT_DESCRIPTION "Scalable, high performance, experimental web server")
message(STATUS "Running CMake for ${PROJECT_NAME} (${PROJECT_DESCRIPTION})")

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/src/cmake")

include_directories(${CMAKE_BINARY_DIR})

include(CheckCCompilerFlag)
include(CheckCSourceCompiles)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CodeCoverage)
include(EnableCFlag)
include(FindPkgConfig)
include(TrySanitizer)
include(GNUInstallDirs)

if (NOT CMAKE_BUILD_TYPE)
	message(STATUS "No build type selected, defaulting to Debug")
	set(CMAKE_BUILD_TYPE "Debug")
endif ()

#
# Find libraries
#
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)
set(ADDITIONAL_LIBRARIES ${ZLIB_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
if (NOT ZLIB_INCLUDES STREQUAL "")
	include_directories(${ZLIB_INCLUDES})
endif ()

foreach (pc_file luajit lua lua51 lua5.1 lua-5.1)
	if (${pc_file} STREQUAL "luajit")
		pkg_check_modules(LUA luajit>=2.0 luajit<2.2)
		set(LWAN_HAVE_LUA_JIT 1)
	else ()
		pkg_check_modules(LUA ${pc_file}>=5.1.0 ${pc_file}<=5.1.999)
	endif ()
	if (LUA_FOUND)
		list(APPEND ADDITIONAL_LIBRARIES "${LUA_LDFLAGS}")
		include_directories(${LUA_INCLUDE_DIRS})
		break()
	endif()
endforeach ()
if (NOT LUA_FOUND)
	message(STATUS "Disabling Lua support")
else ()
	message(STATUS "Building with Lua support using ${LUA_LIBRARIES}")
	set(LWAN_HAVE_LUA 1)
endif ()

option(ENABLE_BROTLI "Enable support for brotli" "ON")
if (ENABLE_BROTLI)
	pkg_check_modules(BROTLI libbrotlienc libbrotlidec libbrotlicommon)
endif ()
if (BROTLI_FOUND)
	list(APPEND ADDITIONAL_LIBRARIES "${BROTLI_LDFLAGS}")
	if (NOT BROTLI_INCLUDE_DIRS STREQUAL "")
		include_directories(${BROTLI_INCLUDE_DIRS})
	endif ()
	set(LWAN_HAVE_BROTLI 1)
endif ()

option(ENABLE_ZSTD "Enable support for zstd" "ON")
if (ENABLE_ZSTD)
	pkg_check_modules(ZSTD libzstd)
endif ()
if (ZSTD_FOUND)
	list(APPEND ADDITIONAL_LIBRARIES "${ZSTD_LDFLAGS}")
	if (NOT ZSTD_INCLUDE_DIRS STREQUAL "")
		include_directories(${ZSTD_INCLUDE_DIRS})
	endif ()
	set(LWAN_HAVE_ZSTD 1)
endif ()

option(ENABLE_TLS "Enable support for TLS (Linux-only)" "ON")
if (ENABLE_TLS)
	check_include_file(linux/tls.h LWAN_HAVE_LINUX_TLS_H)
	if (LWAN_HAVE_LINUX_TLS_H)
		# TLS support requires Linux, as Lwan uses the kTLS flavor
		# only supported there.
		# TODO: Try using BearSSL instead of mbedTLS and only link
		# against things that are absolutely necessary to perform
		# a TLS 1.2 handshake to inform the kernel about the keys.
		find_library(MBEDTLS NAMES mbedtls)
		if (NOT ${MBEDTLS} STREQUAL "MBEDTLS-NOTFOUND")
			find_library(MBEDTLS_CRYPTO NAMES mbedcrypto REQUIRED)
			find_library(MBEDTLS_X509 NAMES mbedx509 REQUIRED)

			message(STATUS "Building with Linux kTLS + mbedTLS at ${MBEDTLS}")
			set(LWAN_HAVE_MBEDTLS 1)
			list(APPEND ADDITIONAL_LIBRARIES ${MBEDTLS} ${MBEDTLS_CRYPTO} ${MBEDTLS_X509})
		else ()
			message(STATUS "mbedTLS not found: not building with TLS support")
		endif ()
	else ()
		message(STATUS "<linux/tls.h> not found: not building with TLS support")
	endif ()
endif ()

option(USE_ALTERNATIVE_MALLOC "Use alternative malloc implementations" "OFF")
if (USE_ALTERNATIVE_MALLOC)
	unset(ALTMALLOC_LIBS CACHE)
	unset(ALTMALLOC_LIBRARY CACHE)

	if (${USE_ALTERNATIVE_MALLOC} STREQUAL "mimalloc")
		set(ALTMALLOC_LIBS mimalloc)
	elseif (${USE_ALTERNATIVE_MALLOC} STREQUAL "tcmalloc")
		set(ALTMALLOC_LIBS tcmalloc_minimal tcmalloc)
	elseif (${USE_ALTERNATIVE_MALLOC} STREQUAL "jemalloc")
		set(ALTMALLOC_LIBS jemalloc)
	else ()
		set(ALTMALLOC_LIBS "mimalloc tcmalloc_minimal tcmalloc jemalloc")
	endif()

	find_library(ALTMALLOC_LIBRARY NAMES ${ALTMALLOC_LIBS})
	if (ALTMALLOC_LIBRARY)
		message(STATUS "Using alternative malloc (${USE_ALTERNATIVE_MALLOC}): ${ALTMALLOC_LIBRARY}")
		list(PREPEND ADDITIONAL_LIBRARIES ${ALTMALLOC_LIBRARY})
	endif ()
endif ()

###
# syslog
option(USE_SYSLOG "Enable syslog" "OFF")
if (${USE_SYSLOG} STREQUAL "ON" AND LWAN_HAVE_SYSLOG_FUNC)
    set(LWAN_HAVE_SYSLOG 1)
endif ()
if (LWAN_HAVE_SYSLOG)
    message(STATUS "Using syslog/rsyslog for logging.")
endif ()

#
# Look for C library functions
#

set(CMAKE_EXTRA_INCLUDE_FILES
	fcntl.h
	stdlib.h
	sys/socket.h
	sys/types.h
	string.h
	time.h
	unistd.h
	dlfcn.h
	syslog.h
)
check_include_file(linux/capability.h LWAN_HAVE_LINUX_CAPABILITY)
check_include_file(sys/auxv.h LWAN_HAVE_SYS_AUXV)
check_include_file(sys/epoll.h LWAN_HAVE_EPOLL)
check_include_files("sys/time.h;sys/types.h;sys/event.h" LWAN_HAVE_SYS_EVENT)
if (LWAN_HAVE_SYS_EVENT)
	set(CMAKE_EXTRA_INCLUDE_FILES
		${CMAKE_EXTRA_INCLUDE_FILES}
		sys/event.h sys/types.h sys/time.h
	)
	check_function_exists(kqueue LWAN_HAVE_KQUEUE)
	check_function_exists(kqueue1 LWAN_HAVE_KQUEUE1)
endif ()
check_include_file(alloca.h LWAN_HAVE_ALLOCA_H)
if (LWAN_HAVE_SYS_AUXV)
	set(CMAKE_EXTRA_INCLUDE_FILES
		${CMAKE_EXTRA_INCLUDE_FILES}
		sys/auxv.h
	)
	check_function_exists(getauxval LWAN_HAVE_GETAUXVAL)
endif ()

set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_THREAD_LIBS_INIT})

check_function_exists(get_current_dir_name LWAN_HAVE_GET_CURRENT_DIR_NAME)
check_symbol_exists(reallocarray stdlib.h LWAN_HAVE_REALLOCARRAY)
check_symbol_exists(eventfd sys/eventfd.h LWAN_HAVE_EVENTFD)
check_function_exists(mempcpy LWAN_HAVE_MEMPCPY)
check_function_exists(memrchr LWAN_HAVE_MEMRCHR)
check_function_exists(pipe2 LWAN_HAVE_PIPE2)
check_function_exists(accept4 LWAN_HAVE_ACCEPT4)
check_function_exists(readahead LWAN_HAVE_READAHEAD)
check_function_exists(mkostemp LWAN_HAVE_MKOSTEMP)
check_function_exists(clock_gettime LWAN_HAVE_CLOCK_GETTIME)
check_function_exists(pthread_barrier_init LWAN_HAVE_PTHREADBARRIER)
check_function_exists(pthread_set_name_np LWAN_HAVE_PTHREAD_SET_NAME_NP)
check_function_exists(posix_fadvise LWAN_HAVE_POSIX_FADVISE)
check_function_exists(getentropy LWAN_HAVE_GETENTROPY)
check_function_exists(fwrite_unlocked LWAN_HAVE_FWRITE_UNLOCKED)
check_function_exists(gettid LWAN_HAVE_GETTID)
check_function_exists(secure_getenv LWAN_HAVE_SECURE_GETENV)
check_function_exists(statfs LWAN_HAVE_STATFS)
check_function_exists(syslog LWAN_HAVE_SYSLOG_FUNC)
check_function_exists(stpcpy LWAN_HAVE_STPCPY)

# This is available on -ldl in glibc, but some systems (such as OpenBSD)
# will bundle these in the C library.  This isn't required for glibc anyway,
# as there's getauxval(), with a fallback to reading the link
# /proc/self/exe.
check_function_exists(dladdr LWAN_HAVE_DLADDR)

if (NOT LWAN_HAVE_CLOCK_GETTIME AND ${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	list(APPEND ADDITIONAL_LIBRARIES rt)
endif ()


#
# Ensure compiler is compatible with GNU11 standard
#
check_c_compiler_flag(-std=gnu11 LWAN_HAVE_STD_GNU11)
if (NOT LWAN_HAVE_STD_GNU11)
	message(FATAL_ERROR "Compiler does not support -std=gnu11. Consider using a newer compiler")
endif()


#
# Check for GCC builtin functions
#
check_c_source_compiles("int main(void) { __builtin_cpu_init(); }" LWAN_HAVE_BUILTIN_CPU_INIT)
check_c_source_compiles("int main(void) { __builtin_expect_with_probability(0, 0, 0); }" LWAN_HAVE_BUILTIN_EXPECT_PROBABILITY)
check_c_source_compiles("int main(void) { __builtin_clzll(0); }" LWAN_HAVE_BUILTIN_CLZLL)
check_c_source_compiles("int main(void) { __builtin_fpclassify(0, 0, 0, 0, 0, 0.0f); }" LWAN_HAVE_BUILTIN_FPCLASSIFY)
check_c_source_compiles("int main(void) { unsigned long long p; (void)__builtin_mul_overflow(0, 0, &p); }" LWAN_HAVE_BUILTIN_MUL_OVERFLOW)
check_c_source_compiles("int main(void) { unsigned long long p; (void)__builtin_add_overflow(0, 0, &p); }" LWAN_HAVE_BUILTIN_ADD_OVERFLOW)
check_c_source_compiles("int main(void) { _Static_assert(1, \"\"); }" LWAN_HAVE_STATIC_ASSERT)
check_c_source_compiles("#include <linux/filter.h>
#include <sys/socket.h>
#include <stddef.h>
int main(void) {
	setsockopt(0, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, NULL, 0);
}" LWAN_HAVE_SO_ATTACH_REUSEPORT_CBPF)
check_c_source_compiles("#include <sys/socket.h>
#include <stddef.h>
int main(void) {
	setsockopt(0, SOL_SOCKET, SO_INCOMING_CPU, NULL, 0);
}" LWAN_HAVE_SO_INCOMING_CPU)

#
# Look for Valgrind header
#
find_path(VALGRIND_INCLUDE_DIR valgrind.h /usr/include /usr/include/valgrind /usr/local/include /usr/local/include/valgrind)
if (VALGRIND_INCLUDE_DIR)
	message(STATUS "Building with Valgrind support")
	include_directories(${VALGRIND_INCLUDE_DIR})

	set(LWAN_HAVE_VALGRIND 1)
else ()
	message(STATUS "Valgrind headers not found -- disabling valgrind support")
endif()

option(MTUNE_NATIVE "Build with -mtune=native/-march=native" "ON")
if (MTUNE_NATIVE)
    enable_c_flag_if_avail(-mtune=native C_FLAGS_REL LWAN_HAVE_MTUNE_NATIVE)
    enable_c_flag_if_avail(-march=native C_FLAGS_REL LWAN_HAVE_MARCH_NATIVE)
endif ()

enable_c_flag_if_avail(-fstack-protector-explicit CMAKE_C_FLAGS
	LWAN_HAVE_STACK_PROTECTOR_EXPLICIT)

#
# Check if immediate binding and read-only global offset table flags
# can be used
#
if (APPLE)
	enable_c_flag_if_avail(-Wl,-bind_at_load CMAKE_EXE_LINKER_FLAGS
		LWAN_HAVE_IMMEDIATE_BINDING)
else ()
	enable_c_flag_if_avail(-Wl,-z,now CMAKE_EXE_LINKER_FLAGS
		LWAN_HAVE_IMMEDIATE_BINDING)
	enable_c_flag_if_avail(-Wl,-z,relro CMAKE_EXE_LINKER_FLAGS
		LWAN_HAVE_READ_ONLY_GOT)
	enable_c_flag_if_avail(-fno-plt CMAKE_C_FLAGS
		LWAN_HAVE_NO_PLT)
	enable_c_flag_if_avail(-Wl,-z,noexecstack CMAKE_EXE_LINKER_FLAGS
		LWAN_HAVE_NOEXEC_STACK)
endif ()

if (${CMAKE_BUILD_TYPE} MATCHES "Rel")
	enable_c_flag_if_avail(-falign-functions=32 C_FLAGS_REL LWAN_HAVE_ALIGN_FNS)
	enable_c_flag_if_avail(-fno-semantic-interposition C_FLAGS_REL LWAN_HAVE_NO_SEMANTIC_INTERPOSITION)
	enable_c_flag_if_avail(-malign-data=abi C_FLAGS_REL LWAN_HAVE_ALIGN_DATA)
	enable_c_flag_if_avail(-fno-asynchronous-unwind-tables C_FLAGS_REL LWAN_HAVE_NO_ASYNC_UNWIND_TABLES)

	enable_c_flag_if_avail(-fPIC -flto C_FLAGS_REL LWAN_HAVE_LTO)

	enable_c_flag_if_avail(-ffat-lto-objects C_FLAGS_REL LWAN_HAVE_LTO_FAT_OBJS)
	enable_c_flag_if_avail(-mcrc32 C_FLAGS_REL LWAN_HAVE_BUILTIN_IA32_CRC32)
endif ()

if (${CMAKE_BUILD_TYPE} MATCHES "Deb")
	option(SANITIZER "Use sanitizer (undefined, address, thread, none)" "none")

	if (${SANITIZER} MATCHES "(undefined|ub|ubsan)")
		try_sanitizer("undefined")
	elseif (${SANITIZER} MATCHES "(address|memory)")
		try_sanitizer("address")
	elseif (${SANITIZER} MATCHES "(thread|race)")
		try_sanitizer("thread")
	else ()
		message(STATUS "Building without a sanitizer")
	endif ()
endif ()

#
# These warnings are only supported by GCC, and some only in newer versions.
#
enable_warning_if_supported(-Waggressive-loop-optimizations)
enable_warning_if_supported(-Warith-conversion)
enable_warning_if_supported(-Warray-bounds)
enable_warning_if_supported(-Wdouble-promotion)
enable_warning_if_supported(-Wduplicated-branches)
enable_warning_if_supported(-Wduplicated-cond)
enable_warning_if_supported(-Wformat-overflow)
enable_warning_if_supported(-Wlogical-not-parentheses)
enable_warning_if_supported(-Wlogical-op)
enable_warning_if_supported(-Wno-override-init)
enable_warning_if_supported(-Wno-unused-parameter)
enable_warning_if_supported(-Wrestrict)
enable_warning_if_supported(-Wstringop-overflow)
enable_warning_if_supported(-Wstringop-overread)
enable_warning_if_supported(-Wstringop-truncation)
enable_warning_if_supported(-Wunsequenced)
enable_warning_if_supported(-Wvla)

# While a useful warning, this is giving false positives.
enable_warning_if_supported(-Wno-free-nonheap-object)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow -Wconversion -std=gnu11")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${C_FLAGS_REL}")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} ${C_FLAGS_REL}")
set(CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL} ${C_FLAGS_REL}")
add_definitions("-D_FILE_OFFSET_BITS=64")
add_definitions("-D_TIME_BITS=64")

if (APPLE)
	set(LWAN_COMMON_LIBS -Wl,-force_load lwan-static)
else ()
	set(LWAN_COMMON_LIBS -Wl,-whole-archive lwan-static -Wl,-no-whole-archive)
endif ()

if (NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^x86_64|amd64|aarch64")
	set(LWAN_HAVE_LIBUCONTEXT 1)
endif ()

include_directories(src/lib)
include_directories(BEFORE src/lib/missing)

#
# Generate lwan-build-config.h
#
add_definitions(-include ${CMAKE_BINARY_DIR}/lwan-build-config.h)
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/src/cmake/lwan-build-config.h.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/lwan-build-config.h"
)
install(
	FILES ${CMAKE_CURRENT_BINARY_DIR}/lwan-build-config.h
	DESTINATION "include/lwan"
)


#
# Generate pkg-config file
#
set(PKG_CONFIG_REQUIRES "")
set(PKG_CONFIG_LIBDIR "\${prefix}/lib")
set(PKG_CONFIG_INCLUDEDIR "\${prefix}/include/lwan")

string (REPLACE ";" " " ADDITIONAL_LIBRARIES_STR "${ADDITIONAL_LIBRARIES}")
set(PKG_CONFIG_LIBS "-L\${libdir} -llwan ${ADDITIONAL_LIBRARIES_STR}")
unset(ADDITIONAL_LIBRARIES_STR)
set(PKG_CONFIG_CFLAGS "-I\${includedir}")

execute_process(
	COMMAND git log -1 --format=%h
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	OUTPUT_VARIABLE PROJECT_VERSION
	OUTPUT_STRIP_TRAILING_WHITESPACE
)
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/src/cmake/lwan.pc.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc"
)
install(FILES "${CMAKE_BINARY_DIR}/${PROJECT_NAME}.pc" DESTINATION lib/pkgconfig)


#
# Set up testsuite and benchmark targets
#
find_package(Python3 COMPONENTS Interpreter)
if (LUA_FOUND AND Python3_Interpreter_FOUND)
	add_custom_target(testsuite
		COMMAND ${Python3_EXECUTABLE}
			${PROJECT_SOURCE_DIR}/src/scripts/testsuite.py -v ${CMAKE_BINARY_DIR}
		DEPENDS testrunner techempower
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		COMMENT "Running test suite.")

	add_custom_target(benchmark
		COMMAND ${Python3_EXECUTABLE}
			${PROJECT_SOURCE_DIR}/src/scripts/benchmark.py
			${CMAKE_BINARY_DIR}/src/bin/testrunner/testrunner
		DEPENDS testrunner weighttp
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		COMMENT "Running benchmark.")
endif()

add_subdirectory(src)

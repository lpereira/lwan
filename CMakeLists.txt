project(lwan C)
cmake_minimum_required(VERSION 2.8.10)
set(PROJECT_DESCRIPTION "Scalable, high performance, experimental web server")
message(STATUS "Running CMake for ${PROJECT_NAME} (${PROJECT_DESCRIPTION})")

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/src/cmake")

include(CheckCCompilerFlag)
include(CheckCSourceCompiles)
include(CheckFunctionExists)
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

find_program(CCACHE ccache)
if (CCACHE)
       message(STATUS "Using ccache from ${CCACHE}")
       set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ${CCACHE})
       set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ${CCACHE})
endif ()

#
# Find libraries
#
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)
set(ADDITIONAL_LIBRARIES ${ZLIB_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

foreach (pc_file luajit lua lua51 lua5.1 lua-5.1)
	if (${pc_file} STREQUAL "luajit")
		pkg_check_modules(LUA luajit>=2.0 luajit<=2.0.999)
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
	set(HAVE_LUA 1)
endif ()

option(USE_ALTERNATIVE_MALLOC "Use alternative malloc implementations" OFF)
if (USE_ALTERNATIVE_MALLOC)
	find_library(TCMALLOC_LIBRARY NAMES tcmalloc_minimal tcmalloc)
	if (TCMALLOC_LIBRARY)
		message(STATUS "tcmalloc found: ${TCMALLOC_LIBRARY}")
		list(APPEND ADDITIONAL_LIBRARIES ${TCMALLOC_LIBRARY})
	else ()
		find_library(JEMALLOC_LIBRARY NAMES jemalloc)
		if (JEMALLOC_LIBRARY)
			message(STATUS "jemalloc found: ${JEMALLOC_LIBRARY}")
			list(APPEND ADDITIONAL_LIBRARIES ${JEMALLOC_LIBRARY})
		else ()
			message(STATUS "jemalloc and tcmalloc were not found, using system malloc")
		endif()
	endif()
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
)
check_include_file(linux/capability.h HAVE_LINUX_CAPABILITY)
check_include_file(sys/auxv.h HAVE_SYS_AUXV)
check_include_file(sys/epoll.h HAVE_EPOLL)
check_include_files("sys/time.h;sys/types.h;sys/event.h" HAVE_SYS_EVENT)
if (HAVE_SYS_EVENT)
	set(CMAKE_EXTRA_INCLUDE_FILES
		${CMAKE_EXTRA_INCLUDE_FILES}
		sys/event.h sys/types.h sys/time.h
	)
	check_function_exists(kqueue HAVE_KQUEUE)
endif ()
check_include_file(alloca.h HAVE_ALLOCA_H)
if (HAVE_SYS_AUXV)
	set(CMAKE_EXTRA_INCLUDE_FILES
		${CMAKE_EXTRA_INCLUDE_FILES}
		sys/auxv.h
	)
	check_function_exists(getauxval HAVE_GETAUXVAL)
endif ()

set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_THREAD_LIBS_INIT})

check_function_exists(rawmemchr HAVE_RAWMEMCHR)
check_function_exists(get_current_dir_name HAVE_GET_CURRENT_DIR_NAME)
check_function_exists(reallocarray HAVE_REALLOCARRAY)
check_function_exists(mempcpy HAVE_MEMPCPY)
check_function_exists(memrchr HAVE_MEMRCHR)
check_function_exists(pipe2 HAVE_PIPE2)
check_function_exists(accept4 HAVE_ACCEPT4)
check_function_exists(readahead HAVE_READAHEAD)
check_function_exists(mkostemp HAVE_MKOSTEMP)
check_function_exists(clock_gettime HAVE_CLOCK_GETTIME)
check_function_exists(pthread_barrier_init HAVE_PTHREADBARRIER)
check_function_exists(pthread_set_name_np HAVE_PTHREAD_SET_NAME_NP)
check_function_exists(eventfd HAVE_EVENTFD)
check_function_exists(posix_fadvise HAVE_POSIX_FADVISE)
check_function_exists(getentropy HAVE_GETENTROPY)

# This is available on -ldl in glibc, but some systems (such as OpenBSD)
# will bundle these in the C library.  This isn't required for glibc anyway,
# as there's getauxval(), with a fallback to reading the link
# /proc/self/exe.
check_function_exists(dladdr HAVE_DLADDR)

if (NOT HAVE_CLOCK_GETTIME AND ${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	list(APPEND ADDITIONAL_LIBRARIES rt)
endif ()


#
# Ensure compiler is compatible with GNU99 standard
#
check_c_compiler_flag(-std=gnu99 HAVE_STD_GNU99)
if (NOT HAVE_STD_GNU99)
	message(FATAL_ERROR "Compiler does not support -std=gnu99. Consider using a newer compiler")
endif()


#
# Check for GCC builtin functions
#
check_c_source_compiles("int main(void) { __builtin_cpu_init(); }" HAVE_BUILTIN_CPU_INIT)
check_c_source_compiles("int main(void) { __builtin_clzll(0); }" HAVE_BUILTIN_CLZLL)
check_c_source_compiles("int main(void) { __builtin_fpclassify(0, 0, 0, 0, 0, 0.0f); }" HAVE_BUILTIN_FPCLASSIFY)
check_c_source_compiles("int main(void) { unsigned long long p; (void)__builtin_mul_overflow(0, 0, &p); }" HAVE_BUILTIN_MUL_OVERFLOW)
check_c_source_compiles("int main(void) { unsigned long long p; (void)__builtin_add_overflow(0, 0, &p); }" HAVE_BUILTIN_ADD_OVERFLOW)
check_c_source_compiles("int main(void) { _Static_assert(1, \"\"); }" HAVE_STATIC_ASSERT)


#
# Look for Valgrind header
#
find_path(VALGRIND_INCLUDE_DIR valgrind.h /usr/include /usr/include/valgrind /usr/local/include /usr/local/include/valgrind)
if (VALGRIND_INCLUDE_DIR)
	message(STATUS "Building with Valgrind support")
	include_directories(${VALGRIND_INCLUDE_DIR})

	set(HAVE_VALGRIND 1)
else ()
	message(STATUS "Valgrind headers not found -- disabling valgrind support")
endif()


enable_c_flag_if_avail(-mtune=native C_FLAGS_REL HAVE_MTUNE_NATIVE)
enable_c_flag_if_avail(-march=native C_FLAGS_REL HAVE_MARCH_NATIVE)

enable_c_flag_if_avail(-fstack-protector-explicit CMAKE_C_FLAGS
	HAVE_STACK_PROTECTOR_EXPLICIT)

#
# Check if immediate binding and read-only global offset table flags
# can be used
#
if (APPLE)
	enable_c_flag_if_avail(-Wl,-bind_at_load CMAKE_EXE_LINKER_FLAGS
		HAVE_IMMEDIATE_BINDING)
else ()
	enable_c_flag_if_avail(-Wl,-z,now CMAKE_EXE_LINKER_FLAGS
		HAVE_IMMEDIATE_BINDING)
	enable_c_flag_if_avail(-Wl,-z,relro CMAKE_EXE_LINKER_FLAGS
		HAVE_READ_ONLY_GOT)
	enable_c_flag_if_avail(-fno-plt CMAKE_C_FLAGS
		HAVE_NO_PLT)
	enable_c_flag_if_avail(-Wl,-z,noexecstack CMAKE_EXE_LINKER_FLAGS
		HAVE_NOEXEC_STACK)
endif ()


if (${CMAKE_BUILD_TYPE} MATCHES "Rel")
	enable_c_flag_if_avail(-malign-data=abi C_FLAGS_REL HAVE_ALIGN_DATA)
	enable_c_flag_if_avail(-fno-asynchronous-unwind-tables C_FLAGS_REL HAVE_NO_ASYNC_UNWIND_TABLES)

	enable_c_flag_if_avail(-flto=jobserver C_FLAGS_REL HAVE_LTO_JOBSERVER)
	if (NOT HAVE_LTO_JOBSERVER)
		enable_c_flag_if_avail(-flto C_FLAGS_REL HAVE_LTO)
	endif ()

	enable_c_flag_if_avail(-ffat-lto-objects C_FLAGS_REL HAVE_LTO_FAT_OBJS)
	enable_c_flag_if_avail(-mcrc32 C_FLAGS_REL HAVE_BUILTIN_IA32_CRC32)
else ()
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
enable_warning_if_supported(-Wduplicated-cond)
enable_warning_if_supported(-Wduplicated-branches)
enable_warning_if_supported(-Wlogical-op)
enable_warning_if_supported(-Wrestrict)
enable_warning_if_supported(-Wdouble-promotion)
enable_warning_if_supported(-Wno-unused-parameter)
enable_warning_if_supported(-Wstringop-truncation)
enable_warning_if_supported(-Wvla)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow -Wconversion -std=gnu99")
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
find_package(PythonInterp 3)
if (LUA_FOUND AND PYTHONINTERP_FOUND)
	add_custom_target(testsuite
		COMMAND ${PYTHON_EXECUTABLE}
			${PROJECT_SOURCE_DIR}/src/scripts/testsuite.py -v
			${CMAKE_BINARY_DIR}/src/bin/testrunner/testrunner
		DEPENDS testrunner
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		COMMENT "Running test suite.")

	add_custom_target(benchmark
		COMMAND ${PYTHON_EXECUTABLE}
			${PROJECT_SOURCE_DIR}/src/scripts/benchmark.py
			${CMAKE_BINARY_DIR}/src/bin/testrunner/testrunner
		DEPENDS testrunner
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		COMMENT "Running benchmark.")
endif()

add_subdirectory(src)

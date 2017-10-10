project(lwan C)
cmake_minimum_required(VERSION 2.8)
set(PROJECT_DESCRIPTION "Scalable, high performance, experimental web server")
message(STATUS "Running CMake for ${PROJECT_NAME} (${PROJECT_DESCRIPTION})")

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/src/cmake")

include(CheckCCompilerFlag)
include(CheckCSourceCompiles)
include(CheckFunctionExists)
include(CodeCoverage)
include(EnableCFlag)
include(FindPkgConfig)
include(TrySanitizer)

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

foreach (pc_file luajit lua lua51 lua5.1 lua-5.1)
	if (${pc_file} STREQUAL "luajit")
		pkg_check_modules(LUA luajit>=2.0 luajit<=2.0.999)
	else ()
		pkg_check_modules(LUA ${pc_file}>=5.1.0 ${pc_file}<=5.1.999)
	endif ()
	if (LUA_FOUND)
		list(APPEND ADDITIONAL_LIBRARIES "-l${LUA_LIBRARIES} ${LUA_LDFLAGS}")
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


#
# Look for C library functions
#
set(CMAKE_EXTRA_INCLUDE_FILES string.h)
check_function_exists(rawmemchr HAS_RAWMEMCHR)
set(HAS_RAWMEMCHR ${HAS_RAWMEMCHR})

set(CMAKE_EXTRA_INCLUDE_FILES stdlib.h)
check_function_exists(reallocarray HAS_REALLOCARRAY)
set(HAS_REALLOCARRAY ${HAS_REALLOCARRAY})

check_function_exists(mempcpy HAS_MEMPCPY)
set(HAS_MEMPCPY ${HAS_MEMPCPY})

check_function_exists(memrchr HAS_MEMRCHR)
set(HAS_MEMRCHR ${HAS_MEMRCHR})

set(CMAKE_EXTRA_INCLUDE_FILES unistd.h)
check_function_exists(pipe2 HAS_PIPE2)
set(HAS_PIPE2 ${HAS_PIPE2})

set(CMAKE_EXTRA_INCLUDE_FILES sys/types.h sys/socket.h)
check_function_exists(accept4 HAS_ACCEPT4)
set(HAS_ACCEPT4 ${HAS_ACCEPT4})

set(CMAKE_EXTRA_INCLUDE_FILES fcntl.h)
check_function_exists(readahead HAS_READAHEAD)
set(HAS_READAHEAD ${HAS_READAHEAD})

set(CMAKE_EXTRA_INCLUDE_FILES time.h)
check_function_exists(clock_gettime HAS_CLOCK_GETTIME)
if (NOT HAS_CLOCK_GETTIME AND ${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	list(APPEND ADDITIONAL_LIBRARIES rt)
endif ()

set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_THREAD_LIBS_INIT})
check_function_exists(pthread_barrier_init HAS_PTHREADBARRIER)


#
# Ensure compiler is compatible with GNU99 standard
#
check_c_compiler_flag(-std=gnu99 HAS_STD_GNU99)
if (NOT HAS_STD_GNU99)
	message(FATAL_ERROR "Compiler does not support -std=gnu99. Consider using a newer compiler")
endif()


#
# Check for GCC builtin functions
#
check_c_source_compiles("int main(void) { __builtin_cpu_init(); }" HAVE_BUILTIN_CPU_INIT)
check_c_source_compiles("int main(void) { __builtin_clzll(0); }" HAVE_BUILTIN_CLZLL)
check_c_source_compiles("int main(void) { unsigned long long p; (void)__builtin_mul_overflow(0, 0, &p); }" HAVE_BUILTIN_MUL_OVERFLOW)
check_c_source_compiles("int main(void) { unsigned long long p; (void)__builtin_add_overflow(0, 0, &p); }" HAVE_BUILTIN_ADD_OVERFLOW)
check_c_source_compiles("int main(void) { _Static_assert(1, \"\"); }" HAVE_STATIC_ASSERT)


#
# Look for Valgrind header
#
find_path(VALGRIND_INCLUDE_DIR valgrind.h /usr/include /usr/include/valgrind /usr/local/include /usr/local/include/valgrind)
if (VALGRIND_INCLUDE_DIR)
	message(STATUS "Building with Valgrind support")
	set(USE_VALGRIND 1)
else ()
	message(STATUS "Valgrind headers not found -- disabling valgrind support")
endif()


enable_c_flag_if_avail(-mtune=native C_FLAGS_REL HAS_MTUNE_NATIVE)
enable_c_flag_if_avail(-rdynamic CMAKE_EXE_LINKER_FLAGS HAS_RDYNAMIC)

#
# Check if immediate binding and read-only global offset table flags
# can be used
#
if (APPLE)
	enable_c_flag_if_avail(-Wl,-bind_at_load CMAKE_EXE_LINKER_FLAGS
		HAS_IMMEDIATE_BINDING)
else ()
	enable_c_flag_if_avail(-Wl,-z,now CMAKE_EXE_LINKER_FLAGS
		HAS_IMMEDIATE_BINDING)
	enable_c_flag_if_avail(-Wl,-z,relro CMAKE_EXE_LINKER_FLAGS
		HAS_READ_ONLY_GOT)
	enable_c_flag_if_avail(-fno-plt CMAKE_C_FLAGS
		HAS_NO_PLT)
endif ()


if (${CMAKE_BUILD_TYPE} MATCHES "Rel")
	enable_c_flag_if_avail(-malign-data=abi C_FLAGS_REL HAS_ALIGN_DATA)
	enable_c_flag_if_avail(-fno-asynchronous-unwind-tables C_FLAGS_REL HAS_NO_ASYNC_UNWIND_TABLES)
	enable_c_flag_if_avail(-flto C_FLAGS_REL HAS_LTO)
	enable_c_flag_if_avail(-ffat-lto-objects C_FLAGS_REL HAS_LTO_FAT_OBJS)
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

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow -Wconversion -std=gnu99")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${C_FLAGS_REL}")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} ${C_FLAGS_REL}")
set(CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL} ${C_FLAGS_REL}")
add_definitions("-D_FILE_OFFSET_BITS=64")

set(LWAN_COMMON_LIBS lwan-static)
if (CMAKE_COMPILER_IS_GNUCC)
	set(LWAN_COMMON_LIBS -Wl,-whole-archive ${LWAN_COMMON_LIBS} -Wl,-no-whole-archive)
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

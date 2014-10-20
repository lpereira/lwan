project(lwan C)
cmake_minimum_required(VERSION 2.8)

find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)

include(CheckCSourceCompiles)
check_c_source_compiles("int main(void) { __builtin_cpu_init(); }" HAVE_BUILTIN_CPU_INIT)
if (HAVE_BUILTIN_CPU_INIT)
	add_definitions("-DHAVE_BUILTIN_CPU_INIT")
endif ()

include(CheckFunctionExists)
set(CMAKE_EXTRA_INCLUDE_FILES time.h)
check_function_exists(clock_gettime HAS_CLOCK_GETTIME)
if (HAS_CLOCK_GETTIME)
	message(STATUS "libc has clock_gettime(). Good.")
else ()
	set(RT_LIB "-lrt")
	message(STATUS "No clock_gettime() in libc. Linking with -lrt.")
endif ()

find_library(TCMALLOC_LIBRARY
	NAMES tcmalloc_minimal tcmalloc
	PATHS /usr/lib /usr/local/lib)
if (TCMALLOC_LIBRARY)
	message(STATUS "tcmalloc found: ${TCMALLOC_LIBRARY}")
	set(MALLOC_LIB ${TCMALLOC_LIBRARY})
else ()
	find_library(JEMALLOC_LIBRARY
		NAMES jemalloc
		PATHS /usr/lib /usr/local/lib)
	if (JEMALLOC_LIBRARY)
		message(STATUS "jemalloc found: ${JEMALLOC_LIBRARY}")
		set(MALLOC_LIB ${JEMALLOC_LIBRARY})
	else ()
		message(STATUS "jemalloc and tcmalloc were not found, using system malloc")
		set(MALLOC_LIB "")
	endif()
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow -Wconversion -std=gnu99")
add_definitions("-D_FILE_OFFSET_BITS=64")

include(CheckCCompilerFlag)
if (${CMAKE_BUILD_TYPE} MATCHES "Rel")
	message(STATUS "Enabling compiler optimizations")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mtune=native -O2 -flto")

	check_c_compiler_flag(-ffat-lto-objects HAS_FAT_LTO_OBJECTS)
	if (HAS_FAT_LTO_OBJECTS)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffat-lto-objects")
	endif ()

	check_c_compiler_flag(-mcrc32 HAS_CRC32)
	if (HAS_CRC32)
		add_definitions("-DUSE_HARDWARE_CRC32=1")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mcrc32")
	endif ()
else ()
	check_c_compiler_flag(-fsanitize=undefined HAS_UNDEFINED_SANITIZER)
	if (HAS_UNDEFINED_SANITIZER)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined")
	endif ()
endif ()


find_path(VALGRIND_INCLUDE_DIR valgrind.h /usr/include /usr/include/valgrind /usr/local/include /usr/local/include/valgrind)
if (VALGRIND_INCLUDE_DIR)
	message(STATUS "Building with Valgrind support")
	add_definitions("-DUSE_VALGRIND=1")
else ()
	message(STATUS "Valgrind headers not found -- disabling valgrind support")
endif()


add_subdirectory(common)

include_directories(common)
add_subdirectory(lwan)
add_subdirectory(freegeoip)
add_subdirectory(techempower)

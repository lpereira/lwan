project(lwan C)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow -Wconversion -std=gnu99")

if (${CMAKE_BUILD_TYPE} MATCHES "Rel")
	message(STATUS "Enabling compiler optimizations")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mtune=native -O3 -flto")

	include(CheckCCompilerFlag)
	check_c_compiler_flag(-mcrc32 HAS_CRC32)
	if (HAS_CRC32)
		set(USE_HARDWARE_CRC32 1)
		add_definitions("-DUSE_HARDWARE_CRC32=1")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mcrc32")
	endif ()
endif ()

find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)

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

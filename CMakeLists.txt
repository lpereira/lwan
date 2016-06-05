project(lwan C)
cmake_minimum_required(VERSION 2.8)

if (NOT CMAKE_BUILD_TYPE)
	message(STATUS "No build type selected, defaulting to Debug")
	set(CMAKE_BUILD_TYPE "Debug")
endif ()

find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)
set(ADDITIONAL_LIBRARIES ${ZLIB_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})


include(CheckCSourceCompiles)
check_c_source_compiles("int main(void) { __builtin_cpu_init(); }" HAVE_BUILTIN_CPU_INIT)
if (HAVE_BUILTIN_CPU_INIT)
	add_definitions("-DHAVE_BUILTIN_CPU_INIT")
endif ()
check_c_source_compiles("int main(void) { __builtin_clzll(0); }" HAVE_BUILTIN_CLZLL)
if (HAVE_BUILTIN_CLZLL)
	add_definitions("-DHAVE_BUILTIN_CLZLL")
endif ()
check_c_source_compiles("int main(void) { unsigned long long p; (void)__builtin_mul_overflow(0, 0, &p); }" HAVE_BUILTIN_MUL_OVERFLOW)
if (HAVE_BUILTIN_MUL_OVERFLOW)
	add_definitions("-DHAVE_BUILTIN_MUL_OVERFLOW")
endif ()
check_c_source_compiles("int main(void) { _Static_assert(1, \"\"); }" HAVE_STATIC_ASSERT)
if (HAVE_STATIC_ASSERT)
	add_definitions("-DHAVE_STATIC_ASSERT")
endif ()

include(CheckFunctionExists)
set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_THREAD_LIBS_INIT})
check_function_exists(pthread_barrier_init HAS_PTHREADBARRIER)
if (HAS_PTHREADBARRIER)
	add_definitions(-DHAS_PTHREADBARRIER)
endif ()

set(CMAKE_EXTRA_INCLUDE_FILES time.h)
check_function_exists(clock_gettime HAS_CLOCK_GETTIME)
if (HAS_CLOCK_GETTIME)
	add_definitions("-DHAS_CLOCK_GETTIME")
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	add_definitions("-DHAS_CLOCK_GETTIME")
	list(APPEND ADDITIONAL_LIBRARIES rt)
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


set(C_FLAGS_REL "-mtune=native")

include(CheckCCompilerFlag)
if (APPLE)
	check_c_compiler_flag(-Wl,-bind_at_load HAS_IMMEDIATE_BINDING)
	if (HAS_IMMEDIATE_BINDING)
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-bind_at_load")
	endif ()
else ()
	check_c_compiler_flag(-Wl,-z,now HAS_IMMEDIATE_BINDING)
	if (HAS_IMMEDIATE_BINDING)
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,now")
	endif ()

	check_c_compiler_flag(-Wl,-z,relro HAS_READ_ONLY_GOT)
	if (HAS_READ_ONLY_GOT)
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro")
	endif ()
endif ()

if (${CMAKE_BUILD_TYPE} MATCHES "Rel")
	check_c_compiler_flag(-malign-data=cacheline HAS_MALIGN_DATA_CACHELINE)
	if (HAS_MALIGN_DATA_CACHELINE)
		set(C_FLAGS_REL "${C_FLAGS_REL} -malign-data=cacheline")
	endif ()

	check_c_compiler_flag(-fno-asynchronous-unwind-tables HAS_ASYNC_UNWIND_TABLES)
	if (HAS_ASYNC_UNWIND_TABLES)
		set(C_FLAGS_REL "${C_FLAGS_REL} -fno-asynchronous-unwind-tables")
	endif ()

	check_c_compiler_flag(-flto HAS_LTO)
	if (HAS_LTO)
		set(C_FLAGS_REL "${C_FLAGS_REL} -flto")

		check_c_compiler_flag(-ffat-lto-objects HAS_FAT_LTO_OBJECTS)
		if (HAS_FAT_LTO_OBJECTS)
			set(C_FLAGS_REL "${C_FLAGS_REL} -ffat-lto-objects")
		endif ()
	endif ()

	check_c_compiler_flag(-mcrc32 HAVE_BUILTIN_IA32_CRC32)
	if (HAVE_BUILTIN_IA32_CRC32)
		add_definitions("-DHAVE_BUILTIN_IA32_CRC32=1")
		set(C_FLAGS_REL "${C_FLAGS_REL} -mcrc32")
	endif ()
else ()
	option(UBSAN "Build with undefined behavior sanitizer" ON)
	option(ASAN "Build with address sanitizer" OFF)

	if (UBSAN)
		# Set -Werror to catch "argument unused during compilation" warnings
		set(CMAKE_REQUIRED_FLAGS "-Werror -fsanitize=undefined") # Also needs to be a link flag for test to pass
		check_c_compiler_flag("-fsanitize=undefined" HAVE_FLAG_SANITIZE_UNDEFINED)

		set(CMAKE_REQUIRED_FLAGS "-Werror -fcatch-undefined-behavior") # Also needs to be a link flag for test to pass
		check_c_compiler_flag("-fcatch-undefined-behavior" HAVE_FLAG_CATCH_UNDEFINED_BEHAVIOR)

		unset(CMAKE_REQUIRED_FLAGS)

		if(HAVE_FLAG_SANITIZE_UNDEFINED)
			message(STATUS "Build with newer undefined behavior sanitizer")
			set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=undefined")
		elseif(HAVE_FLAG_CATCH_UNDEFINED_BEHAVIOR)
			message(STATUS "Build with older undefined behavior sanitizer")
			set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fcatch-undefined-behavior")
		else()
			message(STATUS "Build without undefined behavior sanitizer")
		endif()
	elseif (ASAN)
		# Set -Werror to catch "argument unused during compilation" warnings
		set(CMAKE_REQUIRED_FLAGS "-Werror -faddress-sanitizer") # Also needs to be a link flag for test to pass
		check_c_compiler_flag("-faddress-sanitizer" HAVE_FLAG_ADDRESS_SANITIZER)

		set(CMAKE_REQUIRED_FLAGS "-Werror -fsanitize=address") # Also needs to be a link flag for test to pass
		check_c_compiler_flag("-fsanitize=address" HAVE_FLAG_SANITIZE_ADDRESS)

		unset(CMAKE_REQUIRED_FLAGS)

		if(HAVE_FLAG_SANITIZE_ADDRESS)
			message(STATUS "Build with newer address sanitizer")
			set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address")
		elseif(HAVE_FLAG_ADDRESS_SANITIZER)
			message(STATUS "Build with older address sanitizer")
			set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -faddress-sanitizer")
		else()
			message(STATUS "Build without address sanitizer")
		endif()
	endif ()
endif ()


find_path(VALGRIND_INCLUDE_DIR valgrind.h /usr/include /usr/include/valgrind /usr/local/include /usr/local/include/valgrind)
if (VALGRIND_INCLUDE_DIR)
	message(STATUS "Building with Valgrind support")
	add_definitions("-DUSE_VALGRIND=1")
else ()
	message(STATUS "Valgrind headers not found -- disabling valgrind support")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow -Wconversion -std=gnu11")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${C_FLAGS_REL}")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} ${C_FLAGS_REL}")
set(CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL} ${C_FLAGS_REL}")
add_definitions("-D_FILE_OFFSET_BITS=64")

add_subdirectory(common)

include_directories(common)

set(LWAN_COMMON_LIBS lwan-static)
if (CMAKE_COMPILER_IS_GNUCC)
	set(LWAN_COMMON_LIBS -Wl,-whole-archive ${LWAN_COMMON_LIBS} -Wl,-no-whole-archive)
endif ()

add_subdirectory(lwan)
add_subdirectory(testrunner)
add_subdirectory(freegeoip)
add_subdirectory(techempower)

set(PKG_CONFIG_REQUIRES ${ADDITIONAL_LIBRARIES})
set(PKG_CONFIG_LIBDIR "\${prefix}/lib")
set(PKG_CONFIG_INCLUDEDIR "\${prefix}/include/lwan")
set(PKG_CONFIG_LIBS "-L\${libdir} -llwan-common")
set(PKG_CONFIG_CFLAGS "-I\${includedir}")

execute_process(
  COMMAND git log -1 --format=%h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE PROJECT_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/lwan.pc.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc"
)

install(FILES "${CMAKE_BINARY_DIR}/${PROJECT_NAME}.pc" DESTINATION lib/pkgconfig)

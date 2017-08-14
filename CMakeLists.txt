project(lwan C)
cmake_minimum_required(VERSION 2.8)

set(PROJECT_DESCRIPTION "Scalable, high performance, experimental web server")


include(CheckCCompilerFlag)
include(CheckCSourceCompiles)
include(CheckFunctionExists)


message(STATUS "Running CMake for ${PROJECT_NAME} (${PROJECT_DESCRIPTION})")


if (NOT CMAKE_BUILD_TYPE)
	message(STATUS "No build type selected, defaulting to Debug")
	set(CMAKE_BUILD_TYPE "Debug")
endif ()

check_c_compiler_flag(-std=gnu99 HAS_STD_GNU99)
if (NOT HAS_STD_GNU99)
	message(FATAL_ERROR "Compiler does not support -std=gnu99. Consider using a newer compiler")
endif()


find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)
set(ADDITIONAL_LIBRARIES ${ZLIB_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

add_definitions(-include ${CMAKE_BINARY_DIR}/lwan-build-config.h)

check_c_source_compiles("int main(void) { __builtin_cpu_init(); }" HAVE_BUILTIN_CPU_INIT)
check_c_source_compiles("int main(void) { __builtin_clzll(0); }" HAVE_BUILTIN_CLZLL)
check_c_source_compiles("int main(void) { unsigned long long p; (void)__builtin_mul_overflow(0, 0, &p); }" HAVE_BUILTIN_MUL_OVERFLOW)
check_c_source_compiles("int main(void) { unsigned long long p; (void)__builtin_add_overflow(0, 0, &p); }" HAVE_BUILTIN_ADD_OVERFLOW)
check_c_source_compiles("int main(void) { _Static_assert(1, \"\"); }" HAVE_STATIC_ASSERT)

set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_THREAD_LIBS_INIT})
check_function_exists(pthread_barrier_init HAS_PTHREADBARRIER)

set(CMAKE_EXTRA_INCLUDE_FILES time.h)
check_function_exists(clock_gettime HAS_CLOCK_GETTIME)
if (NOT HAS_CLOCK_GETTIME AND ${CMAKE_SYSTEM_NAME} MATCHES "Linux")
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


macro (enable_c_flag_if_avail _flag _append_to_var _set_var)
	check_c_compiler_flag(${_flag} ${_set_var})

	if (${_set_var})
		set(${_append_to_var} "${${_append_to_var}} ${_flag}")
	endif ()
endmacro ()

enable_c_flag_if_avail(-mtune=native C_FLAGS_REL HAS_MTUNE_NATIVE)
enable_c_flag_if_avail(-rdynamic CMAKE_EXE_LINKER_FLAGS HAS_RDYNAMIC)

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
	macro(try_sanitizer _type)
		set(OLD_CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS})

		set(SANITIZER_FLAG "-fsanitize=${_type}")
		set(CMAKE_REQUIRED_FLAGS "-Werror ${SANITIZER_FLAG}")

		check_c_compiler_flag(${SANITIZER_FLAG} HAVE_SANITIZER)

		set(CMAKE_REQUIRED_FLAGS ${OLD_CMAKE_REQUIRED_FLAGS})
		unset(OLD_CMAKE_REQUIRED_FLAGS)

		if (HAVE_SANITIZER)
			message(STATUS "Building with ${_type} sanitizer")
			set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${SANITIZER_FLAG}")
		endif ()

		unset(HAVE_SANITIZER)
		unset(SANITIZER_FLAG)
	endmacro ()

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


find_path(VALGRIND_INCLUDE_DIR valgrind.h /usr/include /usr/include/valgrind /usr/local/include /usr/local/include/valgrind)
if (VALGRIND_INCLUDE_DIR)
	message(STATUS "Building with Valgrind support")
	set(USE_VALGRIND 1)
else ()
	message(STATUS "Valgrind headers not found -- disabling valgrind support")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow -Wconversion -std=gnu99")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${C_FLAGS_REL}")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} ${C_FLAGS_REL}")
set(CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL} ${C_FLAGS_REL}")
add_definitions("-D_FILE_OFFSET_BITS=64")

set(LWAN_COMMON_LIBS lwan-static)
if (CMAKE_COMPILER_IS_GNUCC)
	set(LWAN_COMMON_LIBS -Wl,-whole-archive ${LWAN_COMMON_LIBS} -Wl,-no-whole-archive)
endif ()

include_directories(BEFORE common/missing)

add_subdirectory(common)
include_directories(common)

add_subdirectory(testrunner)
if (NOT ${CMAKE_BUILD_TYPE} MATCHES "Coverage")
  add_subdirectory(lwan)
  add_subdirectory(freegeoip)
  add_subdirectory(techempower)
endif()

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
  "${CMAKE_CURRENT_SOURCE_DIR}/lwan-build-config.h.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/lwan-build-config.h"
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/lwan-build-config.h
  DESTINATION "include/lwan")

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/lwan.pc.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc"
)
install(FILES "${CMAKE_BINARY_DIR}/${PROJECT_NAME}.pc" DESTINATION lib/pkgconfig)

find_package(PythonInterp 3)
if (LUA_FOUND AND PYTHONINTERP_FOUND)
	function(add_python_test NAME FILE WORKING_DIRECTORY DEPEND)
		add_custom_target(${NAME}
				COMMAND ${PYTHON_EXECUTABLE} ${FILE}
				DEPENDS ${DEPEND}
				WORKING_DIRECTORY ${WORKING_DIRECTORY}
				COMMENT "Running Python tests: ${FILE}.")
	endfunction()

	add_python_test(testsuite
			${PROJECT_SOURCE_DIR}/tools/testsuite.py
			${PROJECT_SOURCE_DIR}
			testrunner)

	add_python_test(benchmark
			${PROJECT_SOURCE_DIR}/tools/benchmark.py
			${PROJECT_SOURCE_DIR}
			testrunner)
endif()

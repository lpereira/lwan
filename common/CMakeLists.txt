set(SOURCES
	base64.c
	hash.c
	int-to-str.c
	list.c
	lwan.c
	lwan-cache.c
	lwan-config.c
	lwan-coro.c
	lwan-http-authorize.c
	lwan-io-wrappers.c
	lwan-job.c
	lwan-redirect.c
	lwan-request.c
	lwan-response.c
	lwan-rewrite.c
	lwan-serve-files.c
	lwan-socket.c
	lwan-status.c
	lwan-straitjacket.c
	lwan-tables.c
	lwan-template.c
	lwan-thread.c
	lwan-trie.c
	missing.c
	murmur3.c
	patterns.c
	reallocarray.c
	realpathat.c
	sd-daemon.c
	strbuf.c
)

include(CheckFunctionExists)
set(CMAKE_EXTRA_INCLUDE_FILES string.h)
check_function_exists(rawmemchr HAS_RAWMEMCHR)
if (HAS_RAWMEMCHR)
	add_definitions(-DHAS_RAWMEMCHR)
endif ()

check_function_exists(mempcpy HAS_MEMPCPY)
if (HAS_MEMPCPY)
	add_definitions(-DHAS_MEMPCPY)
endif ()

check_function_exists(memrchr HAS_MEMRCHR)
if (HAS_MEMRCHR)
	add_definitions(-DHAS_MEMRCHR)
endif ()

set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_THREAD_LIBS_INIT})
check_function_exists(pthread_timedjoin_np HAS_TIMEDJOIN)
if (HAS_TIMEDJOIN)
	add_definitions(-DHAS_TIMEDJOIN)
endif ()

set(CMAKE_EXTRA_INCLUDE_FILES unistd.h)
check_function_exists(pipe2 HAS_PIPE2)
if (HAS_PIPE2)
	add_definitions(-DHAS_PIPE2)
endif ()

set(CMAKE_EXTRA_INCLUDE_FILES sys/types.h sys/socket.h)
check_function_exists(accept4 HAS_ACCEPT4)
if (HAS_ACCEPT4)
	add_definitions(-DHAS_ACCEPT4)
endif ()

include(FindPkgConfig)
foreach (pc_file luajit lua lua51 lua5.1 lua-5.1)
	if (${pc_file} STREQUAL "luajit")
		pkg_check_modules(LUA luajit>=2.0 luajit<=2.0.999)
	else ()
		pkg_check_modules(LUA ${pc_file}>=5.1.0 ${pc_file}<=5.1.999)
	endif ()
        if (LUA_FOUND)
		list(APPEND ADDITIONAL_LIBRARIES "-l${LUA_LIBRARIES} ${LUA_LDFLAGS}")
		list(APPEND SOURCES lwan-lua.c)
		include_directories(${LUA_INCLUDE_DIRS})
		add_definitions(-DHAVE_LUA)
		break()
        endif()
endforeach ()
if (NOT LUA_FOUND)
	message(STATUS "Disabling Lua support")
else ()
	message(STATUS "Building with Lua support using ${LUA_LIBRARIES}")
endif ()

add_library(lwan-static STATIC ${SOURCES})
set_target_properties(lwan-static PROPERTIES
   OUTPUT_NAME lwan CLEAN_DIRECT_OUTPUT 1)
if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
	set_target_properties(lwan-static PROPERTIES COMPILE_FLAGS "-fPIC")
endif()

# Can't call add_library() without source files. Create an empty .c file,
# then link with the static library just recently built.
file(WRITE "${CMAKE_BINARY_DIR}/empty.c" "")
add_library(lwan-shared SHARED "${CMAKE_BINARY_DIR}/empty.c")
target_link_libraries(lwan-shared ${LWAN_COMMON_LIBS})
set_target_properties(lwan-shared PROPERTIES
   OUTPUT_NAME lwan CLEAN_DIRECT_OUTPUT 1)

include(ExternalProject)
ExternalProject_Add(
	mimegen
	SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/tools
	PREFIX ${CMAKE_CURRENT_BINARY_DIR}/tools
	CONFIGURE_COMMAND cmake ${CMAKE_SOURCE_DIR}/tools
	BUILD_COMMAND make
	INSTALL_COMMAND ln -sf ${CMAKE_CURRENT_BINARY_DIR}/tools/src/mimegen-build/mimegen ${CMAKE_CURRENT_BINARY_DIR}/mimegen
)

add_dependencies(lwan-static mimegen)

add_custom_command(
	OUTPUT ${CMAKE_BINARY_DIR}/mime-types.h
	COMMAND ${CMAKE_BINARY_DIR}/common/mimegen ${CMAKE_SOURCE_DIR}/tools/mime.types > ${CMAKE_BINARY_DIR}/mime-types.h
	DEPENDS ${CMAKE_SOURCE_DIR}/tools/mime.types mimegen
)
add_custom_target(generate_mime_types_table DEPENDS ${CMAKE_BINARY_DIR}/mime-types.h)
add_dependencies(lwan-static generate_mime_types_table)
include_directories(${CMAKE_BINARY_DIR})

set(ADDITIONAL_LIBRARIES ${ADDITIONAL_LIBRARIES} PARENT_SCOPE)

INSTALL(TARGETS lwan-static lwan-shared
  DESTINATION "lib"
)
INSTALL(FILES lwan.h lwan-coro.h lwan-trie.h lwan-status.h strbuf.h hash.h
  lwan-template.h lwan-serve-files.h lwan-config.h missing.h
  DESTINATION "include/lwan" )

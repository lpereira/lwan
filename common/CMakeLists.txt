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
	murmur3.c
	patterns.c
	reallocarray.c
	realpathat.c
	strbuf.c
	sd-daemon.c
	missing.c
)

include(CheckIncludeFiles)
check_include_files(sys/epoll.h HAVE_EPOLL_H)
if (NOT HAVE_EPOLL_H)
	list(APPEND SOURCES epoll-bsd.c)
endif ()


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
		list(APPEND ADDITIONAL_LIBRARIES ${LUA_LIBRARIES})
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

find_package(PythonInterp)
if (NOT PYTHONINTERP_FOUND)
	message(FATAL_ERROR "Could not find Python interpreter")
endif ()

add_library(lwan-common STATIC ${SOURCES})

add_custom_command(
	OUTPUT ${CMAKE_BINARY_DIR}/mime-types.h
	COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tools/generate-mime-types-table.py ${CMAKE_SOURCE_DIR}/tools/mime.types > ${CMAKE_BINARY_DIR}/mime-types.h
	DEPENDS ${CMAKE_SOURCE_DIR}/tools/mime.types ${CMAKE_SOURCE_DIR}/tools/generate-mime-types-table.py
)
add_custom_target(generate_mime_types_table DEPENDS ${CMAKE_BINARY_DIR}/mime-types.h)
add_dependencies(lwan-common generate_mime_types_table)
include_directories(${CMAKE_BINARY_DIR})

set(ADDITIONAL_LIBRARIES ${ADDITIONAL_LIBRARIES} PARENT_SCOPE)

INSTALL(TARGETS lwan-common
  DESTINATION "lib"
)
INSTALL(FILES lwan.h lwan-coro.h lwan-trie.h lwan-status.h strbuf.h hash.h
  lwan-template.h lwan-serve-files.h lwan-config.h missing.h
  DESTINATION "include/lwan" )

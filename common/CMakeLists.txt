set(SOURCES
	base64.c
	hash.c
	int-to-str.c
	list.c
	lwan-array.c
	lwan.c
	lwan-cache.c
	lwan-config.c
	lwan-coro.c
	lwan-http-authorize.c
	lwan-io-wrappers.c
	lwan-job.c
	lwan-mod-redirect.c
	lwan-mod-response.c
	lwan-mod-rewrite.c
	lwan-mod-serve-files.c
	lwan-request.c
	lwan-response.c
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
	realpathat.c
	sd-daemon.c
	strbuf.c
)

include(CheckFunctionExists)
set(CMAKE_EXTRA_INCLUDE_FILES string.h)
check_function_exists(rawmemchr HAS_RAWMEMCHR)
set(HAS_RAWMEMCHR ${HAS_RAWMEMCHR} PARENT_SCOPE)

check_function_exists(reallocarray HAS_REALLOCARRAY)
set(HAS_REALLOCARRAY ${HAS_REALLOCARRAY} PARENT_SCOPE)

check_function_exists(mempcpy HAS_MEMPCPY)
set(HAS_MEMPCPY ${HAS_MEMPCPY} PARENT_SCOPE)

check_function_exists(memrchr HAS_MEMRCHR)
set(HAS_MEMRCHR ${HAS_MEMRCHR} PARENT_SCOPE)

set(CMAKE_EXTRA_INCLUDE_FILES unistd.h)
check_function_exists(pipe2 HAS_PIPE2)
set(HAS_PIPE2 ${HAS_PIPE2} PARENT_SCOPE)

set(CMAKE_EXTRA_INCLUDE_FILES sys/types.h sys/socket.h)
check_function_exists(accept4 HAS_ACCEPT4)
set(HAS_ACCEPT4 ${HAS_ACCEPT4} PARENT_SCOPE)

include(FindPkgConfig)
foreach (pc_file luajit lua lua51 lua5.1 lua-5.1)
	if (${pc_file} STREQUAL "luajit")
		pkg_check_modules(LUA luajit>=2.0 luajit<=2.0.999)
	else ()
		pkg_check_modules(LUA ${pc_file}>=5.1.0 ${pc_file}<=5.1.999)
	endif ()
	if (LUA_FOUND)
		list(APPEND ADDITIONAL_LIBRARIES "-l${LUA_LIBRARIES} ${LUA_LDFLAGS}")
		list(APPEND SOURCES lwan-lua.c lwan-mod-lua.c)
		include_directories(${LUA_INCLUDE_DIRS})
		break()
	endif()
endforeach ()
if (NOT LUA_FOUND)
	message(STATUS "Disabling Lua support")
else ()
	message(STATUS "Building with Lua support using ${LUA_LIBRARIES}")
	set(HAVE_LUA 1 PARENT_SCOPE)
endif ()


add_library(lwan-static STATIC ${SOURCES})
set_target_properties(lwan-static PROPERTIES
   OUTPUT_NAME lwan CLEAN_DIRECT_OUTPUT 1)
set_target_properties(lwan-static PROPERTIES COMPILE_FLAGS "-fPIC")


# Can't call add_library() without source files. Create an empty .c file,
# then link with the static library just recently built.
file(WRITE "${CMAKE_BINARY_DIR}/empty.c" "")
add_library(lwan-shared SHARED "${CMAKE_BINARY_DIR}/empty.c")
target_link_libraries(lwan-shared ${LWAN_COMMON_LIBS})
set_target_properties(lwan-shared PROPERTIES
   OUTPUT_NAME lwan CLEAN_DIRECT_OUTPUT 1)


# Build mimegen
if (CMAKE_CROSSCOMPILING)
	set(IMPORT_EXECUTABLES "IMPORTFILE-NOTFILE" CACHE FILEPATH)
	include(${IMPORT_EXECUTABLES})
else ()
	add_executable(mimegen
		../tools/mimegen.c
		hash.c
		murmur3.c
		missing.c
	)
	find_library(ZOPFLI_LIBRARY NAMES zopfli PATHS /usr/lib /usr/local/lib)
	if (ZOPFLI_LIBRARY)
		message(STATUS "Using Zopfli (${ZOPFLI_LIBRARY}) for mimegen")
		target_link_libraries(mimegen ${ZOPFLI_LIBRARY})
		target_compile_definitions(mimegen PUBLIC -DHAVE_ZOPFLI=1)
	else ()
		message(STATUS "Using zlib (${ZLIB_LIBRARIES}) for mimegen")
		target_link_libraries(mimegen ${ZLIB_LIBRARIES})
	endif ()
endif ()

add_custom_command(
	OUTPUT ${CMAKE_BINARY_DIR}/mime-types.h
	COMMAND ${CMAKE_BINARY_DIR}/common/mimegen ${CMAKE_SOURCE_DIR}/tools/mime.types > ${CMAKE_BINARY_DIR}/mime-types.h
	DEPENDS ${CMAKE_SOURCE_DIR}/tools/mime.types mimegen
)
add_custom_target(generate_mime_types_table DEPENDS ${CMAKE_BINARY_DIR}/mime-types.h)
add_dependencies(lwan-static generate_mime_types_table)
include_directories(${CMAKE_BINARY_DIR})

if (NOT CMAKE_CROSSCOMPILING)
	export(TARGETS mimegen FILE ${CMAKE_BINARY_DIR}/ImportExecutables.cmake)
endif ()


set(ADDITIONAL_LIBRARIES ${ADDITIONAL_LIBRARIES} -lm PARENT_SCOPE)


get_property(LIB64 GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS)
if ("${LIB64}" STREQUAL "TRUE")
       set(LIBSUFFIX 64)
else ()
       get_property(LIB32 GLOBAL PROPERTY FIND_LIBRARY_USE_LIB32_PATHS)
       if ("${LIB32}" STREQUAL "TRUE")
	       set(LIBSUFFIX 32)
       else ()
	       set(LIBSUFFIX "")
       endif ()
endif ()
set(INSTALL_LIB_DIR lib${LIBSUFFIX} CACHE PATH "Installation directory for libraries")
mark_as_advanced(INSTALL_LIB_DIR)
message(STATUS "Library install directory: ${CMAKE_INSTALL_PREFIX}/${INSTALL_LIB_DIR}")


install(TARGETS lwan-static lwan-shared
  DESTINATION ${INSTALL_LIB_DIR}
)
install(FILES
	hash.h
	lwan-array.h
	lwan-config.h
	lwan-coro.h
	lwan.h
	lwan-mod-serve-files.h
	lwan-mod-rewrite.h
	lwan-mod-response.h
	lwan-mod-redirect.h
	lwan-status.h
	lwan-template.h
	lwan-trie.h
	strbuf.h
  DESTINATION "include/lwan")

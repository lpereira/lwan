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
	lwan-time.c
	missing.c
	murmur3.c
	patterns.c
	realpathat.c
	sd-daemon.c
	strbuf.c
)

if (HAVE_LUA)
	list(APPEND SOURCES lwan-lua.c lwan-mod-lua.c)
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
add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/mime-types.h
        COMMAND ${CMAKE_BINARY_DIR}/src/bin/tools/mimegen
                ${CMAKE_SOURCE_DIR}/src/bin/tools/mime.types >
                ${CMAKE_BINARY_DIR}/mime-types.h
        DEPENDS ${CMAKE_SOURCE_DIR}/src/bin/tools/mime.types mimegen
	COMMENT "Building MIME type table"
)
add_custom_target(generate_mime_types_table
        DEPENDS ${CMAKE_BINARY_DIR}/mime-types.h
)
add_dependencies(lwan-static generate_mime_types_table)

add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/auto-index-icons.h
        COMMAND ${CMAKE_BINARY_DIR}/src/bin/tools/bin2hex
                ${CMAKE_SOURCE_DIR}/wwwroot/icons/back.gif back_gif
                ${CMAKE_SOURCE_DIR}/wwwroot/icons/file.gif file_gif
                ${CMAKE_SOURCE_DIR}/wwwroot/icons/folder.gif
                folder_gif >
                ${CMAKE_BINARY_DIR}/auto-index-icons.h
        DEPENDS ${CMAKE_SOURCE_DIR}/wwwroot/icons/back.gif
                ${CMAKE_SOURCE_DIR}/wwwroot/icons/file.gif
                ${CMAKE_SOURCE_DIR}/wwwroot/icons/folder.gif
                bin2hex
	COMMENT "Bundling auto-index icons"
)
add_custom_target(generate_auto_index_icons
        DEPENDS ${CMAKE_BINARY_DIR}/auto-index-icons.h
)
add_dependencies(lwan-static generate_auto_index_icons)


include_directories(${CMAKE_BINARY_DIR})

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


install(
	TARGETS lwan-static lwan-shared
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

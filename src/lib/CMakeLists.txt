if (CMAKE_CROSSCOMPILING)
	set(IMPORT_EXECUTABLES "IMPORTFILE-NOTFILE" CACHE FILEPATH "Point it to the export file from a native build")
	include(${IMPORT_EXECUTABLES})
endif ()

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
	lwan-readahead.c
	lwan-request.c
	lwan-response.c
	lwan-socket.c
	lwan-status.c
	lwan-straitjacket.c
	lwan-strbuf.c
	lwan-tables.c
	lwan-template.c
	lwan-thread.c
	lwan-time.c
	lwan-trie.c
	missing.c
	missing-pthread.c
	murmur3.c
	patterns.c
	queue.c
	realpathat.c
	sd-daemon.c
	timeout.c
	sha1.c
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
target_link_libraries(lwan-shared
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)
if (NOT APPLE)
	target_link_libraries(lwan-shared
		-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/liblwan.sym
	)
endif ()

set_target_properties(lwan-shared PROPERTIES
   OUTPUT_NAME lwan CLEAN_DIRECT_OUTPUT 1)


# Build mimegen
add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/mime-types.h
        COMMAND mimegen
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
        COMMAND bin2hex
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

if (NOT HAVE_BUILTIN_FPCLASSIFY)
	set(ADDITIONAL_LIBRARIES ${ADDITIONAL_LIBRARIES} -lm PARENT_SCOPE)
endif ()

install(
	TARGETS lwan-static lwan-shared
	DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}
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
	lwan-strbuf.h
	queue.h
	timeout.h
	list.h
  DESTINATION "${CMAKE_INSTALL_FULL_INCLUDEDIR}/lwan")

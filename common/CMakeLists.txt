if (NOT USE_HARDWARE_CRC32)
	set(GENERIC_SOURCES
		murmur3.c
	)
endif ()


add_library(lwan-common STATIC
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
	lwan-request.c
	lwan-response.c
	lwan-serve-files.c
	lwan-socket.c
	lwan-status.c
	lwan-tables.c
	lwan-template.c
	lwan-thread.c
	lwan-trie.c
	realpathat.c
	sd-daemon.c
	strbuf.c
	${GENERIC_SOURCES}
)

find_package(PythonInterp)
if (NOT PYTHONINTERP_FOUND)
	message(FATAL_ERROR "Could not find Python interpreter")
endif ()

add_custom_command(
	OUTPUT ${CMAKE_BINARY_DIR}/mime-types.h
	COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tools/parse-mime-types.py ${CMAKE_SOURCE_DIR}/tools/mime.types > ${CMAKE_BINARY_DIR}/mime-types.h
	DEPENDS ${CMAKE_SOURCE_DIR}/tools/mime.types ${CMAKE_SOURCE_DIR}/tools/parse-mime-types.py
)
add_custom_target(tables_mime_types DEPENDS ${CMAKE_BINARY_DIR}/mime-types.h)
add_dependencies(lwan-common tables_mime_types)
include_directories(${CMAKE_BINARY_DIR})

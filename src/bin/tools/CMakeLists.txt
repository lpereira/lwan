if (CMAKE_CROSSCOMPILING)
	set(IMPORT_EXECUTABLES "IMPORTFILE-NOTFILE" CACHE FILEPATH)
	include(${IMPORT_EXECUTABLES})
else ()
	add_executable(mimegen
		mimegen.c
		${CMAKE_SOURCE_DIR}/src/lib/hash.c
		${CMAKE_SOURCE_DIR}/src/lib/murmur3.c
		${CMAKE_SOURCE_DIR}/src/lib/missing.c
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

	add_executable(bin2hex
		bin2hex.c
	)

	export(TARGETS mimegen FILE ${CMAKE_BINARY_DIR}/ImportExecutables.cmake)
	export(TARGETS bin2hex FILE ${CMAKE_BINARY_DIR}/ImportExecutables.cmake)
endif ()

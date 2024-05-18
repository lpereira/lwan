if (CMAKE_CROSSCOMPILING)
	set(IMPORT_EXECUTABLES "IMPORTFILE-NOTFILE" CACHE FILEPATH "Point it to the export file from a native build")
	include(${IMPORT_EXECUTABLES})
else ()
	add_executable(mimegen
		mimegen.c
		${CMAKE_SOURCE_DIR}/src/lib/hash.c
		${CMAKE_SOURCE_DIR}/src/lib/missing.c
		${CMAKE_SOURCE_DIR}/src/lib/lwan-status.c
	)
	if (LWAN_HAVE_BROTLI)
		message(STATUS "Using Brotli for mimegen")
		target_link_libraries(mimegen ${BROTLI_LDFLAGS})
	elseif (LWAN_HAVE_ZSTD)
		message(STATUS "Using Zstd for mimegen")
		target_link_libraries(mimegen ${ZSTD_LDFLAGS})
	else ()
		find_library(ZOPFLI_LIBRARY NAMES zopfli PATHS /usr/lib /usr/local/lib)
		if (ZOPFLI_LIBRARY)
			message(STATUS "Using Zopfli (${ZOPFLI_LIBRARY}) for mimegen")
			target_link_libraries(mimegen ${ZOPFLI_LIBRARY})
			target_compile_definitions(mimegen PUBLIC -DLWAN_HAVE_ZOPFLI=1)
		else ()
			message(STATUS "Using zlib (${ZLIB_LIBRARIES}) for mimegen")
			target_link_libraries(mimegen ${ZLIB_LIBRARIES})
		endif ()
	endif ()

	add_executable(bin2hex
		bin2hex.c
	)

	add_executable(configdump
		configdump.c
		${CMAKE_SOURCE_DIR}/src/lib/lwan-config.c
		${CMAKE_SOURCE_DIR}/src/lib/lwan-status.c
		${CMAKE_SOURCE_DIR}/src/lib/lwan-strbuf.c
		${CMAKE_SOURCE_DIR}/src/lib/missing.c
		${CMAKE_SOURCE_DIR}/src/lib/hash.c
	)

	add_executable(weighttp weighttp.c)
	target_link_libraries(weighttp ${CMAKE_THREAD_LIBS_INIT})

	add_executable(statuslookupgen statuslookupgen.c)

	export(TARGETS statuslookupgen weighttp configdump mimegen bin2hex FILE ${CMAKE_BINARY_DIR}/ImportExecutables.cmake)
endif ()

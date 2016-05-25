include(FindPkgConfig)
pkg_check_modules(SQLITE sqlite3>=3.6.20)

if (SQLITE_FOUND)
	add_executable(freegeoip
		freegeoip.c
	)

	if (CMAKE_COMPILER_IS_GNUCC)
		target_link_libraries(freegeoip
			-Wl,-whole-archive lwan-common -Wl,-no-whole-archive
			${CMAKE_DL_LIBS}
			${ADDITIONAL_LIBRARIES}
			${SQLITE_LIBRARIES}
		)
	else ()
		target_link_libraries(freegeoip
			-Wl lwan-common
			${CMAKE_DL_LIBS}
			${ADDITIONAL_LIBRARIES}
			${SQLITE_LIBRARIES}
		)
	endif()
else ()
	message(STATUS "Freegeoip sample application not being built: SQLite not found")
endif ()

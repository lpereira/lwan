include(FindPkgConfig)
pkg_check_modules(SQLITE sqlite3>=3.6.20)

if (SQLITE_FOUND)
	add_executable(freegeoip
		freegeoip.c
	)

	target_link_libraries(freegeoip
		-Wl,-whole-archive lwan-common -Wl,-no-whole-archive
		dl
		${ADDITIONAL_LIBRARIES}
		${SQLITE_LIBRARIES}
	)
else ()
	message(STATUS "Freegeoip sample application not being built: SQLite not found")
endif ()

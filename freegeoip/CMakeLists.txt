include(FindPkgConfig)
pkg_check_modules(SQLITE REQUIRED sqlite3>=3.7.9)

add_executable(freegeoip
	freegeoip.c
)

target_link_libraries(freegeoip
	${ADDITIONAL_LIBRARIES}
	${SQLITE_LIBRARIES}
	lwan-common
	dl
)

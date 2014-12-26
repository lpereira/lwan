include(FindPkgConfig)
pkg_check_modules(SQLITE REQUIRED sqlite3>=3.6.20)

add_executable(freegeoip
	freegeoip.c
)

target_link_libraries(freegeoip
	lwan-common
	dl
	${ADDITIONAL_LIBRARIES}
	${SQLITE_LIBRARIES}
)

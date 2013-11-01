include(FindPkgConfig)
pkg_check_modules(SQLITE REQUIRED sqlite3>=3.7.15.2)

add_executable(freegeoip
	freegeoip.c
)

target_link_libraries(freegeoip
	${CMAKE_THREAD_LIBS_INIT}
	${MALLOC_LIB}
	${ZLIB_LIBRARIES}
	${SQLITE_LIBRARIES}
	lwan-common
	dl
)

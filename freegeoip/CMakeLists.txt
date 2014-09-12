include(FindPkgConfig)
pkg_check_modules(SQLITE REQUIRED sqlite3>=3.7.15.2)

add_executable(freegeoip
	freegeoip.c
)

target_link_libraries(freegeoip
	${MALLOC_LIB}
	${SQLITE_LIBRARIES}
	lwan-common
	dl
	${ZLIB_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT}
	${RT_LIB}
)

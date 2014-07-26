include(FindPkgConfig)
pkg_check_modules(SQLITE REQUIRED sqlite3>=3.7.15.2)

add_executable(techempower
	techempower.c
	json.c
)

target_link_libraries(techempower
	${MALLOC_LIB}
	${SQLITE_LIBRARIES}
	lwan-common
	dl
	${ZLIB_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT}
)


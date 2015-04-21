include(FindPkgConfig)
pkg_check_modules(SQLITE sqlite3>=3.6.20)

find_path(MYSQL_INCLUDE_DIR mysql.h
	/usr/local/include/mysql
	/usr/include/mysql
)

if (MYSQL_INCLUDE_DIR AND SQLITE_FOUND)
	message(STATUS "Found MySQL includes at ${MYSQL_INCLUDE_DIR}")
	include_directories(AFTER ${MYSQL_INCLUDE_DIR})

	set(MYSQL_NAMES mysqlclient mysqlclient_r)
	find_library(MYSQL_LIBRARY
		NAMES ${MYSQL_NAMES}
		PATH_SUFFIXES mysql
	)

	if (MYSQL_LIBRARY)
		message(STATUS "Found MySQL client library at ${MYSQL_LIBRARY}")

		add_executable(techempower
			techempower.c
			json.c
			array.c
			database.c
		)

		target_link_libraries(techempower
			lwan-common
			dl
			${ADDITIONAL_LIBRARIES}
			${SQLITE_LIBRARIES}
			${MYSQL_LIBRARY}
		)
	endif ()
endif ()

if (NOT MYSQL_LIBRARY)
	message(STATUS "Not building benchmark suite: database libraries not found.")
endif ()

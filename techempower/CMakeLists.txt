include(FindPkgConfig)
pkg_check_modules(SQLITE REQUIRED sqlite3>=3.7.9)

find_path(MYSQL_INCLUDE_DIR mysql.h
	/usr/local/include/mysql
	/usr/include/mysql
)

if (MYSQL_INCLUDE_DIR)
	message(STATUS "Found MySQL includes at ${MYSQL_INCLUDE_DIR}")
	include_directories(AFTER ${MYSQL_INCLUDE_DIR})
else ()
	message(FATAL "MySQL includes not found")
endif ()

set(MYSQL_NAMES mysqlclient mysqlclient_r)
find_library(MYSQL_LIBRARY
	NAMES ${MYSQL_NAMES}
	PATHS /usr/lib /usr/local/lib
	PATH_SUFFIXES mysql
)

if (MYSQL_LIBRARY)
	message(STATUS "Found MySQL client library at ${MYSQL_LIBRARY}")
else ()
	message(FATAL "MySQL client library not found.")
endif ()

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


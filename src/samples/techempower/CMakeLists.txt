include(FindPkgConfig)
pkg_check_modules(SQLITE sqlite3>=3.6.20)
pkg_check_modules(MARIADB mariadb>=3.3)

if (MARIADB_FOUND AND SQLITE_FOUND)
        add_executable(techempower
                techempower.c
                json.c
                database.c
        )

        target_link_libraries(techempower
                ${LWAN_COMMON_LIBS}
                ${ADDITIONAL_LIBRARIES}
                ${SQLITE_LIBRARIES}
                ${SQLITE_LDFLAGS}
                ${MARIADB_LDFLAGS}
                ${MARIADB_LIBRARIES}
        )
        include_directories(${SQLITE_INCLUDE_DIRS} ${MARIADB_INCLUDE_DIRS})
        include_directories(BEFORE ${CMAKE_BINARY_DIR})

        if (${CMAKE_BUILD_TYPE} MATCHES "Coverage")
                find_package(PythonInterp 3)

                if (PYTHONINTERP_FOUND)
                       add_dependencies(generate-coverage techempower)
                endif()
        endif ()
else ()
	message(STATUS "Not building benchmark suite: database libraries not found.")
endif ()

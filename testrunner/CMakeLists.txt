add_executable(testrunner main.c)

if (CMAKE_COMPILER_IS_GNUCC)
	target_link_libraries(testrunner
		-Wl,-whole-archive lwan-common -Wl,-no-whole-archive
		${CMAKE_DL_LIBS}
		${ADDITIONAL_LIBRARIES}
	)
else ()
	target_link_libraries(testrunner
		-Wl lwan-common
		${CMAKE_DL_LIBS}
		${ADDITIONAL_LIBRARIES}
	)
endif ()

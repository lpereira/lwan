add_executable(lwan main.c)

if (CMAKE_COMPILER_IS_GNUCC)
	target_link_libraries(lwan
		-Wl,-whole-archive lwan-common -Wl,-no-whole-archive
		${CMAKE_DL_LIBS}
		${ADDITIONAL_LIBRARIES}
	)
else ()
	target_link_libraries(lwan
		-Wl,-all_load lwan-common -Wl,-all_load
		${CMAKE_DL_LIBS}
		${ADDITIONAL_LIBRARIES}
	)
endif ()

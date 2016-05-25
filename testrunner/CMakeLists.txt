add_executable(testrunner main.c)

target_link_libraries(testrunner
	${LWAN_COMMON_LIBS}
	${CMAKE_DL_LIBS}
	${ADDITIONAL_LIBRARIES}
)

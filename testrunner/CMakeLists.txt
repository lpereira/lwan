add_executable(testrunner main.c)

target_link_libraries(testrunner
	-Wl,-whole-archive lwan-common -Wl,-no-whole-archive
	${CMAKE_DL_LIBS}
	${ADDITIONAL_LIBRARIES}
)


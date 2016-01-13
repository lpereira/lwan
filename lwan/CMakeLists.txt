add_executable(lwan main.c)

target_link_libraries(lwan
	-Wl,-whole-archive lwan-common -Wl,-no-whole-archive
	${CMAKE_DL_LIBS}
	${ADDITIONAL_LIBRARIES}
)


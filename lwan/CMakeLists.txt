add_executable(lwan main.c)

target_link_libraries(lwan
	${LWAN_COMMON_LIBS}
	${CMAKE_DL_LIBS}
	${ADDITIONAL_LIBRARIES}
)

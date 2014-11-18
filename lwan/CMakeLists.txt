add_executable(lwan main.c)

target_link_libraries(lwan
	${ADDITIONAL_LIBRARIES}
	lwan-common
	dl
)


add_executable(lwan main.c)

target_link_libraries(lwan
	lwan-common
	dl
	${ADDITIONAL_LIBRARIES}
)


add_executable(lwan main.c)

target_link_libraries(lwan
	-Wl,-whole-archive lwan-common -Wl,-no-whole-archive
	dl
	${ADDITIONAL_LIBRARIES}
)


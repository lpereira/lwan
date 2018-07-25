add_executable(clock
	main.c
	gifenc.c
)

target_link_libraries(clock
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)

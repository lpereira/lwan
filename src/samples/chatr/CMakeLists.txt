add_executable(chatr
	main.c
	../techempower/json.c
)

target_link_libraries(chatr
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)

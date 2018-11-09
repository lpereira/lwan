add_executable(websocket
	main.c
)

target_link_libraries(websocket
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)

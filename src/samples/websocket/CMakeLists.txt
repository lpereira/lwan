add_executable(websocket
	main.c
)

target_link_libraries(websocket
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)

add_custom_command(
	OUTPUT ${CMAKE_BINARY_DIR}/websocket-sample.h
	COMMAND bin2hex
		${CMAKE_SOURCE_DIR}/src/samples/websocket/index.html index_html > ${CMAKE_BINARY_DIR}/websocket-sample.h
	DEPENDS ${CMAKE_SOURCE_DIR}/src/samples/websocket/index.html
		bin2hex
	COMMENT "Bundling websocket sample index"
)
add_custom_target(generate_websocket_sample
	DEPENDS ${CMAKE_BINARY_DIR}/websocket-sample.h
)

add_dependencies(websocket generate_websocket_sample)

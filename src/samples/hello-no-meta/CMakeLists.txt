add_executable(hello-no-meta
	main.c
)

target_link_libraries(hello-no-meta
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)

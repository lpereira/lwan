add_executable(pastebin
	main.c
)

target_link_libraries(pastebin
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)

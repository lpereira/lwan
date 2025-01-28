add_executable(forthsalon
	main.c
)

target_link_libraries(forthsalon
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)

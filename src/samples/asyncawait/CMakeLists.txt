add_executable(asyncawait
	main.c
)

target_link_libraries(asyncawait
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)

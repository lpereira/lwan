add_executable(forth
	forth.c
)

target_compile_options(forth PRIVATE -DMAIN -DDUMP_CODE)

target_link_libraries(forth
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
	m
)

add_executable(forthsalon
	forth.c
	main.c
)

ADD_DEFINITIONS(-fstack-usage)

target_link_libraries(forthsalon
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
	m
)

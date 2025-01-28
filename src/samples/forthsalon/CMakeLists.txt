add_executable(forth
	forth.c
)

target_compile_options(forth PRIVATE -DMAIN)

target_link_libraries(forth
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
	m
)

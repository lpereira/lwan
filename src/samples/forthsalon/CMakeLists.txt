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

target_compile_options(forthsalon PRIVATE -DDUMP_CODE)

target_link_libraries(forthsalon
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
	m
)

add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/forth-jit-inc.h
        COMMAND bin2hex
                ${CMAKE_SOURCE_DIR}/src/samples/forthsalon/forth-jit.h forth_jit
                >
                ${CMAKE_BINARY_DIR}/forth-jit-inc.h
        DEPENDS ${CMAKE_SOURCE_DIR}/src/samples/forthsalon/forth-jit.h
                bin2hex
        COMMENT "Bundling data for forthsalon sample"
)
add_custom_target(forth_jit_data
        DEPENDS ${CMAKE_BINARY_DIR}/forth-jit-inc.h
)
add_dependencies(forth forth_jit_data)
add_dependencies(forthsalon forth_jit_data)

include_directories(BEFORE ${CMAKE_BINARY_DIR})

add_executable(fuzz
	fuzz.c
)

target_link_libraries(fuzz
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
	-fsanitize=fuzzer,memory
	-fprofile-instr-generate
	-fcoverage-mapping 
)

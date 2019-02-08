include_directories(BEFORE ${CMAKE_BINARY_DIR})

add_executable(fuzz
	fuzz.cc
)

target_link_libraries(fuzz
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
	-fsanitize=fuzzer,${BUILD_FUZZER}
)

include_directories(BEFORE ${CMAKE_BINARY_DIR})

add_executable(request_fuzzer request_fuzzer.cc)

target_link_libraries(request_fuzzer
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
	-fsanitize=fuzzer,${BUILD_FUZZER}
)

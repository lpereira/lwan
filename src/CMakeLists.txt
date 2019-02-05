add_subdirectory(lib)
add_subdirectory(bin)

if (NOT BUILD_FUZZER)
	add_subdirectory(samples)
endif ()

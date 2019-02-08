add_subdirectory(lib)
add_subdirectory(bin)

if (NOT INSTURMENT_FOR_FUZZING)
	add_subdirectory(samples)
endif ()

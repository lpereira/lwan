add_subdirectory(tools)

if (INSTRUMENT_FOR_FUZZING)
	add_subdirectory(fuzz)
else ()
	if (NOT ${CMAKE_BUILD_TYPE} MATCHES "Coverage")
		add_subdirectory(lwan)
	endif()

	add_subdirectory(testrunner)
endif ()

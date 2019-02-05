add_subdirectory(tools)

if (BUILD_FUZZER)
	add_subdirectory(fuzz)
else ()
	if (NOT ${CMAKE_BUILD_TYPE} MATCHES "Coverage")
		add_subdirectory(lwan)
	endif()

	add_subdirectory(testrunner)
endif ()

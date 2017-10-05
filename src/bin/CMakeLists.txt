if (NOT ${CMAKE_BUILD_TYPE} MATCHES "Coverage")
	add_subdirectory(tools)
	add_subdirectory(lwan)
endif()

add_subdirectory(testrunner)

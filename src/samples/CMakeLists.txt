if (NOT ${CMAKE_BUILD_TYPE} MATCHES "Coverage")
	add_subdirectory(freegeoip)
	add_subdirectory(techempower)
endif()

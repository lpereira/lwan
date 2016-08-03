add_executable(testrunner main.c)

target_link_libraries(testrunner
	${LWAN_COMMON_LIBS}
	${CMAKE_DL_LIBS}
	${ADDITIONAL_LIBRARIES}
)

if (${CMAKE_BUILD_TYPE} MATCHES "Coverage")
	find_package(PythonInterp 3)

	if (PYTHONINTERP_FOUND)
		include(CodeCoverage.cmake)

		setup_target_for_coverage(generate-coverage
			"${PYTHON_EXECUTABLE} ${CMAKE_HOME_DIRECTORY}/tools/testsuite.py $<TARGET_FILE:testrunner>"
			coverage
		)
		message(STATUS "Python found; generate-coverage target enabled")
	else ()
		message(STATUS "Python not found; coverage report disabled")
	endif()
endif ()

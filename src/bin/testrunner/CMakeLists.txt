include_directories(BEFORE ${CMAKE_BINARY_DIR})

add_executable(testrunner main.c)

target_link_libraries(testrunner
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)

if (${CMAKE_BUILD_TYPE} MATCHES "Coverage")
	include(CodeCoverage)

	if (Python3_Interpreter_FOUND)
		setup_target_for_coverage_lcov(
			NAME generate-coverage
			EXECUTABLE ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/src/scripts/testsuite.py -v ${CMAKE_BINARY_DIR}
			DEPENDENCIES testrunner
			BASE_DIRECTORY "${CMAKE_SOURCE_DIR}"
		)
		message(STATUS "Python found; generate-coverage target enabled")
	else ()
		message(STATUS "Python not found; coverage report disabled")
	endif()
endif ()

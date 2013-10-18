add_executable(lwan main.c)

target_link_libraries(lwan
	${CMAKE_THREAD_LIBS_INIT}
	${MALLOC_LIB}
	${ZLIB_LIBRARIES}
	lwan-common
)


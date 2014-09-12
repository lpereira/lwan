add_executable(lwan main.c)

target_link_libraries(lwan
	${MALLOC_LIB}
	lwan-common
	dl
	${ZLIB_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT}
	${RT_LIB}
)


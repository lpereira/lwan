project(lwan C)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow -Werror")

find_package(Threads)

add_library(wan
	lwan.c
	lwan-trie.c
	lwan-sendfile.c
	lwan-serve-files.c
	int-to-str.c
)

target_link_libraries(wan
	${CMAKE_THREAD_LIBS_INIT})
set_target_properties(wan
	PROPERTIES PREFIX "l")

add_executable(lwan
	main.c)

target_link_libraries(lwan
	wan
	${CMAKE_THREAD_LIBS_INIT})

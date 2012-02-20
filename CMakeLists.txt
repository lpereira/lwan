project(lwan C)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow -Werror")

find_package(Threads)

add_executable(lwan
	lwan.c
	lwan-trie.c
	lwan-sendfile.c
	lwan-serve-files.c
	lwan-hello-world.c
	int-to-str.c)
target_link_libraries(lwan
	${CMAKE_THREAD_LIBS_INIT})

	

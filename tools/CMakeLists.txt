project(lwan-tools C)
cmake_minimum_required(VERSION 2.8)

project(mimegen)

find_package(ZLIB REQUIRED)
set(ADDITIONAL_LIBRARIES ${ZLIB_LIBRARIES})

include_directories(BEFORE ${CMAKE_BINARY_DIR} ../common/missing)

add_executable(mimegen
	mimegen.c
	../common/hash.c
	../common/murmur3.c
	../common/reallocarray.c
)

find_library(ZOPFLI_LIBRARY NAMES zopfli PATHS /usr/lib /usr/local/lib)
if (ZOPFLI_LIBRARY)
	message(STATUS "Using Zopfli (${ZOPFLI_LIBRARY}) for mimegen")
	target_link_libraries(mimegen ${ZOPFLI_LIBRARY})
	set (HAVE_ZOPFLI 1)
else ()
	message(STATUS "Using zlib (${ZLIB_LIBRARIES}) for mimegen")
	target_link_libraries(mimegen ${ZLIB_LIBRARIES})
endif ()

configure_file(${CMAKE_SOURCE_DIR}/../lwan-build-config.h.cmake
	${CMAKE_BINARY_DIR}/lwan-build-config.h)

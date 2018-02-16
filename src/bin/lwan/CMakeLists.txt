include_directories(BEFORE ${CMAKE_BINARY_DIR})

add_executable(lwan main.c)

target_link_libraries(lwan
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)

INSTALL(TARGETS lwan DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})

add_executable(smolsite
	main.c
	junzip.c
)

target_link_libraries(smolsite
	${LWAN_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)

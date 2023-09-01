
find_program(ZIP NAMES zip)
if (ZIP)
        add_executable(smolsite
                main.c
                junzip.c
        )

        target_link_libraries(smolsite
                ${LWAN_COMMON_LIBS}
                ${ADDITIONAL_LIBRARIES}
        )

        add_custom_command(
                OUTPUT ${CMAKE_BINARY_DIR}/smolsite.zip
                COMMAND ${ZIP} -DXjq9 ${CMAKE_BINARY_DIR}/smolsite.zip ${CMAKE_SOURCE_DIR}/src/samples/smolsite/index.html
                DEPENDS ${CMAKE_SOURCE_DIR}/src/samples/smolsite/index.html
                COMMENT "Zipping smolsite ZIP"
        )
        add_custom_target(generate_smolsite_zip
                DEPENDS ${CMAKE_BINARY_DIR}/smolsite.zip
        )

        add_custom_command(
                OUTPUT ${CMAKE_BINARY_DIR}/smolsite.h
                COMMAND bin2hex
                        ${CMAKE_SOURCE_DIR}/src/samples/smolsite/smolsite.html smolsite_html
                        ${CMAKE_BINARY_DIR}/smolsite.zip smolsite_zip > ${CMAKE_BINARY_DIR}/smolsite.h
                DEPENDS ${CMAKE_SOURCE_DIR}/src/samples/smolsite/smolsite.html
                        ${CMAKE_BINARY_DIR}/smolsite.zip
                        bin2hex
                COMMENT "Bundling smolsite template"
        )
        add_custom_target(generate_smolsite
                DEPENDS ${CMAKE_BINARY_DIR}/smolsite.h
        )

        add_dependencies(smolsite generate_smolsite generate_smolsite_zip)
endif ()

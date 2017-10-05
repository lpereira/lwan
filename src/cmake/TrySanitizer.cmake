macro(try_sanitizer _type)
        set(OLD_CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS})

        set(SANITIZER_FLAG "-fsanitize=${_type}")
        set(CMAKE_REQUIRED_FLAGS "-Werror ${SANITIZER_FLAG}")

        check_c_compiler_flag(${SANITIZER_FLAG} HAVE_SANITIZER)

        set(CMAKE_REQUIRED_FLAGS ${OLD_CMAKE_REQUIRED_FLAGS})
        unset(OLD_CMAKE_REQUIRED_FLAGS)

        if (HAVE_SANITIZER)
                message(STATUS "Building with ${_type} sanitizer")
                set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${SANITIZER_FLAG}")
        endif ()

        unset(HAVE_SANITIZER)
        unset(SANITIZER_FLAG)
endmacro ()

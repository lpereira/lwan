macro (enable_c_flag_if_avail _flag _append_to_var _set_var)
	check_c_compiler_flag(${_flag} ${_set_var})

	if (${_set_var})
		set(${_append_to_var} "${${_append_to_var}} ${_flag}")
	endif ()
endmacro ()


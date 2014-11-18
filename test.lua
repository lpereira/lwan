
function entry_point()
	name = lwan.query_param("name")
	if name then
		lwan.set_response("Hello, " .. name .. "!")
	else
		lwan.set_response("Hello, World!")
	end
end




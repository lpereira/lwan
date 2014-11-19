function handle_get_hello()
	name = lwan.query_param("name")
	if name then
		lwan.set_response("Hello, " .. name .. "!")
	else
		lwan.set_response("Hello, World!")
	end
end

function handle_get_chunked()
	for i = 0, 10 do
		lwan.say("Chunk #" .. i .. "\n")
	end
end

function handle_get_random()
	lwan.set_response("Random number: " .. math.random())
end

function string.starts(String, Start)
   -- From http://lua-users.org/wiki/StringRecipes
   return string.sub(String, 1, string.len(Start)) == Start
end

function handle_get_root()
	for key, value in pairs(_G) do
		if string.starts(key, "handle_get_") and type(value) == "function" then
			lwan.say("<li><a href=" .. string.sub(key, 12) .. ">" .. key .. "</a></li>\n")
		end
	end	
end

function handle_get_hello(req)
	local name = req:query_param[[name]]
	if name then
		req:set_response("Hello, " .. name .. "!")
	else
		req:set_response("Hello, World!")
	end
end

function handle_get_chunked(req)
	for i = 0, 10 do
		req:say("Chunk #" .. i .. "\n")
	end
end

function handle_get_random(req)
	req:set_response("Random number: " .. math.random())
end

function string.starts(String, Start)
   -- From http://lua-users.org/wiki/StringRecipes
   return string.sub(String, 1, string.len(Start)) == Start
end

function handle_get_root(req)
	for key, value in pairs(_G) do
		if string.starts(key, "handle_get_") and type(value) == "function" then
			req:say("<li><a href=" .. string.sub(key, 12) .. ">" .. key .. "</a></li>\n")
		end
	end	
end

function handle_get_hello(req)
    local name = req:query_param[[name]]
    if name then
        req:set_response("Hello, " .. name .. "!")
    else
        req:set_response("Hello, World!")
    end
end

function handle_get_cookie(req)
    req:set_headers({
        ["Set-Cookie"] = {
            "SESSION_ID=1234; HttpOnly",
            "LANG=pt_BR"
        },
        ['Other-Header'] = 'some random value',
        ['Yet-Another-Header'] = '42'
    })

    local foo = req:cookie[[FOO]]
    if foo then
        req:set_response("Cookie FOO has value: " .. foo)
    else
        req:set_response("Cookie FOO not set")
    end
end

function handle_get_sse(req)
    for i = 0, 10 do
        req:send_event("counter-changed", "event" .. i)
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

function is_get_handler(s, func)
    if string.starts(s, "handle_get_") then
        return type(func) == "function"
    end
    return false
end

function handle_get_root(req)
    for key, value in pairs(_G) do
        if is_get_handler(key, value) then
            req:say("<li><a href=" .. string.sub(key, 12) .. ">" .. key .. "</a></li>\n")
        end
    end
end

RequestInfo = {}
RequestInfo.__index = function(self, key)
    if key == "https" then
        self.https = self.request:is_https()
        return self.https
    elseif key == "http_version" then
        self.http_version = self.request:http_version()
        return self.http_version
    elseif key == "request_method" then
        self.http_method = self.request:http_method()
        return self.http_method
    elseif key == "http_headers" then
        self.http_headers = self.request:http_headers()
        return self.http_headers
    elseif key == "num_headers" then
        self.num_http_headers = self.request:num_http_headers()
        return self.num_http_headers
    elseif key == "remote_addr" then
        self.remote_addr = self.request:remote_address()
        return self.remote_addr
    elseif key == "uri" then
        self.request_uri = self.request:path()
        return self.request_uri
    elseif key == "query_string" then
        self.query_string = self.request:query_string()
        return self.query_string
    end
end

function RequestInfo.new(request)
    return setmetatable({ request = request }, RequestInfo)
end

Mongoose = {}
Mongoose.__index = function(self, key)
    if key == "write" then
        self.write = function(arg) return self.request:write(arg) end
        return self.write
    elseif key == "request_info" then
        self.request_info = RequestInfo.new(self.request)
        return self.request_info
    elseif key == "read" then
        self.read = function() return self.request:body() end
        return self.read
    elseif key == "cry" then
        self.cry = Lwan.log.error
        return self.cry
    elseif key == "version" then
        self.version = self.request:version()
        return self.version
    elseif key == "system" then
        self.system = self.request:operating_system()
        return self.system
    elseif key == "get_mime_type" then
        self.get_mime_type = function(arg) return self.request:get_mime_type(arg) end
        return self.get_mime_type
    elseif key == "base64_encode" then
        self.base64_encode = function(arg) return self.request:base64_encode(arg) end
        return self.base64_encode
    elseif key == "base64_decode" then
        self.base64_decode = function(arg) return self.request:base64_decode(arg) end
        return self.base64_decode
    elseif key == "get_var" then
        self.get_var = function(arg) return self.request:query_param(arg) end
        return self.get_var
    elseif key == "random" then
        self.random = function() return self.request:random_double() end
        return self.random
    end
end

function Mongoose.new(request)
    return setmetatable({ request = request }, Mongoose)
end

function handle(__request)
    local mg = Mongoose.new(__request)

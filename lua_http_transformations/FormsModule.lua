local urlencode = require 'urlencode'

local FormsModule = {}

-- Returns a table containing form parameters
function FormsModule.getPostParams(body)
    result = {}
    if body then
        local reqBody = body..'&'
        for nev in reqBody:gmatch("(.-)&") do
            local validNVP = true
            local n = nil
            local v = nil
            nev = nev..'='
            for nvp in nev:gmatch("(.-)=") do
                if validNVP then
                    if not n then
                        n = urlencode.decode_url(nvp)
                    elseif not v then
                        v = urlencode.decode_url(nvp)
                    else
                        -- there were more than two matches, this is bad
                        validNVP = false
                        n = nil
                        v = nil
                    end
                end
            end
            if (n and v) then
                result[n] = v
            end
        end
    end
    return result
end

function FormsModule.getPostBody(paramMap)
    local result = ""
    local first = true
    for k,v in pairs(paramMap) do
        if not first then
            result = result .. '&'
        end
        first = false
        result = result .. k
        result = result .. '='
        result = result .. urlencode.encode_url(v)
    end
    return result
end

function FormsModule.getQueryParams(url)
    result = {}
    _,_,qs = string.find(url, "%?(.+)")
    if qs then
        result = FormsModule.getPostParams(qs)
    end
    
    return result
end

return FormsModule
--[[
	A transformation that looks at the response body of the JWKS endpoint and filters out any entries that contain an x5c object with any entries that 
    are expired.

	================
	[http-transformations]
	jwks_filter_expired = jwks_filter_expired.lua

	[http-transformations:jwks_filter_expired]
	request-match = response:GET /mga/sps/jwks*
	=============

    Note that the max size of the response body is capped by the setting of the parameter
    [server]
    request-body-max-read 

    The default is 32768, so if your JWKS size is larger (it almost certainly is) then you need to increase this.

--]]

local cjson = require 'cjson'
local baseutils = require 'basexx'
local x509 = require 'openssl.x509'

local logger = require 'LoggingUtils'

--[[
    validateKeyX5C
    If k contains x5c, check each certificate for expiry
    Returns true if either x5c is absent, or for each entry in x5c there is nothing expired
--]]
function validateKeyX5C(k)
    local anyExpired = false
    if k["x5c"] ~= nil then
        for i, pemStr in pairs(k["x5c"]) do
            local c = x509.new("-----BEGIN CERTIFICATE-----\n" .. pemStr .. "\n-----END CERTIFICATE-----", "PEM")
            local nbf, exp = c:getLifetime()
            -- logger.debugLog("nbf: " .. nbf .. " exp: " .. exp)
            local now = os.time()
            if nbf > now or exp < now then
                anyExpired = true
            end
        end
    end
    if anyExpired then
        logger.debugLog("Skipping key: " .. cjson.encode(k))
    end
    return (not anyExpired)
end




local newRspJSON =cjson.decode('{"keys":[]}')
local rspBody = HTTPResponse.getBody()
--logger.debugLog("rspBody: " .. rspBody)
local rspBodyJSON = cjson.decode(rspBody)
if rspBodyJSON ~= nil then
    if rspBodyJSON["keys"] ~= nil then
        for i, k in pairs(rspBodyJSON["keys"]) do
            --logger.debugLog("i: " .. i .. " k: " .. cjson.encode(k))
            if (validateKeyX5C(k)) then
                table.insert(newRspJSON["keys"], k)
            end
        end
        HTTPResponse.setBody(cjson.encode(newRspJSON))
    else
        logger.debugLog("Response body did not contain keys")
    end
else
    logger.debugLog("Unable to decode response body as JSON")
end

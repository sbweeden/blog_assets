--[[
	A transformation that looks at the response body of the JWKS endpoint and filters out any entries that don't have an x5c with a DN 
    corresponding to a known "map table" defined as a constant in this transformation rule.

	================
	[http-transformations]
	jwks_filter_app = jwks_filter_app.lua

	[http-transformations:jwks_filter_app]
	request-match = response:GET /mga/sps/oauth/oauth20/jwks/*
	=============

    Note that the max size of the response body is capped by the setting of the parameter
    [server]
    request-body-max-read 

    The default is 32768, so if your JWKS size is larger (it almost certainly is) then you need to increase this.

--]]

local cjson = require 'cjson'
local x509 = require 'openssl.x509'

local logger = require 'LoggingUtils'

-- For each "OIDC / OAuth definition", contains a list of the lower case (important)  subject DNs for certificates we want that JWKS endpoint to expose
local definitionNameToCNList = cjson.decode('{"myOIDCDefinition":["cn=isam,o=ibm,c=us","cn=digicert tls hybrid ecc sha384 2020 ca1,o=digicert inc,c=us"]}')

-- set definitionName to the text after the last forward slash in the request URL
local _, _, definitionName = string.find(HTTPRequest.getURL(), ".*/(%a+)")
-- logger.debugLog("definitionName: " .. definitionName)

--[[
Checks if a table has a value
--]]
local function hasValue (tab, val)
    if tab == nil then
        return false
    end
    for k,v in ipairs(tab) do
        if v == val then
            return true
        end
    end

    return false
end


--[[
    buildSubjectDN
    Reconstructs a lowercase subject DN string from an X509 name
--]]
function buildSubjectDN(sbj)
    local result = ''
    --[[
    The X509 name pairs pairs come in reverse order of the DN we want to construct, for example

    buildSubjectDN.k: 1 -- buildSubjectDN.v: {["blob"] = us,["ln"] = countryName,["sn"] = C,["id"] = 2.5.4.6} -- 
    buildSubjectDN.k: 2 -- buildSubjectDN.v: {["blob"] = ibm,["ln"] = organizationName,["sn"] = O,["id"] = 2.5.4.10} -- 
    buildSubjectDN.k: 3 -- buildSubjectDN.v: {["blob"] = isam,["ln"] = commonName,["sn"] = CN,["id"] = 2.5.4.3}
    --]]
    for k,v in pairs(sbj:all()) do
        local component = string.lower(v["sn"] .. "=" .. v["blob"]) 
        -- add a comma except for the first component (which is the last part of the DN)
        if (not (k == 1)) then
            component = component .. ","
        end
        -- prepend this component to what we have built so far
        result = component .. result
    end
    -- logger.debugLog("buildSubjectDN.result: " .. result)
    return result
end


--[[
    validateKeyX5C
    If k contains x5c, check the DN of each entry in x5c is within the list of allowed DNs 
    Returns true if at least one x5c contains a DN that matches on of the DNs in definitionNameToCNList for the current definitionName
--]]
function validateKeyX5C(k)
    local anyMatchedDN = false
    if k["x5c"] ~= nil then
        for i, pemStr in pairs(k["x5c"]) do
            local c = x509.new("-----BEGIN CERTIFICATE-----\n" .. pemStr .. "\n-----END CERTIFICATE-----", "PEM")

            local subjectDN = buildSubjectDN(c:getSubject())

            -- now do any of the strings in the definitionNameToCNList for the current definitionName match?
            if (hasValue(definitionNameToCNList[definitionName], subjectDN)) then
                -- logger.debugLog("validateKeyX5C found a matched DN: " .. subjectDN)
                anyMatchedDN = true
            end

        end
    end

    return anyMatchedDN
end

if (definitionNameToCNList[definitionName] == nil) then
    logger.debugLog("Not filtering because no filter defined for definition name: " .. definitionName)
else
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
end

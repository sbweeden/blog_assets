--[[
	A response transformation that replaces some magic string macros in the response page with
    values from the credential.

	================
	[http-transformations]
	credential_macros = credential_macros.lua

	[http-transformations:credential_macros]
	request-match = response:GET /y.html *
	=============

    Note that the max size of the response body is capped by the setting of the parameter
    [server]
    request-body-max-read 

    The default is 32768, so if your page is larger than that, you need to increase this.
--]]
local cjson = require 'cjson'
local logger = require 'LoggingUtils'

-- List of macros to the attributes that are used to replace them. Each "value" in this object
-- has both the attribute name, and a flag to indicate if that attribute should be considered
-- multi-valued
local macroToAttrList = cjson.decode('{"@USERNAME@":{"attrName":"AZN_CRED_PRINCIPAL_NAME","isMv":false},"@GROUPS@": {"attrName":"AZN_CRED_GROUPS","isMv":true}}')

-- Simple way to HTML encode a string
function htmlEncode(s)
    local result = ''
    result = string.gsub(s, '&', '&amp;');
    result = string.gsub(result, '<', '&lt;');
    result = string.gsub(result, '>', '&gt;');
    result = string.gsub(result, '"', '&quot;');
    return result
end

--
-- Main entry point starts here
--
local rspBody = HTTPResponse.getBody()
--logger.debugLog("rspBody: " .. rspBody)
for i, k in pairs(macroToAttrList) do
    if (Session.containsCredentialAttribute(k.attrName)) then
        local replacementString = nil
        if (k.isMv) then
            -- multi-valued attribute, build a comma-separated string
            replacementString = logger.dumpAsString((Session.getMvCredentialAttribute(k.attrName)))
        else
            -- single-valued attribute
            replacementString = Session.getCredentialAttribute(k.attrName)
        end
        -- htmlEncode the replacementString during injection
        rspBody = string.gsub(rspBody, i, htmlEncode(replacementString));
    end
end
HTTPResponse.setBody(rspBody)

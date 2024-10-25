--[[
	A response transformation that takes a particular credential attribute and adds
    its values to a request HTTP header
--]]
local cjson = require 'cjson'
local urlencode = require 'urlencode'

--
-- Utility function that takes a multi-valued attribute (table) and converts it into
-- a string to be downstreamed as a HTTP header, similar to how WebSEAL formats iv-groups.
--
function mvAttrToHTTPHeader(mvAttr, urlEncodeValues)
    local s = ''
    local first = true
    for k,v in pairs(mvAttr) do

        -- if not the first value, add a comma
        if not first then
          s = s .. ','
        end
       
       first = false

       -- quote character before value
       s = s .. '"'

       -- value, perhaps url encoded
       if (urlEncodeValues) then
        s = s .. urlencode.encode_url(v)
       else
         s = s .. v
       end

       -- quote character after value
       s = s .. '"'
    end
    return s
end


-- List of headers to the attributes that are used to populate them. Each "value" in this object
-- has both the attribute name, and a flag to indicate if that attribute should be considered
-- multi-valued
local headerToAttrList = cjson.decode('{"Xtra-Azn-Registry-ID1":{"attrName":"AZN_CRED_PRINCIPAL_NAME","isMv":false},"Xtra-iv-groups": {"attrName":"blueGroups","isMv":true}}')

--
-- Main entry point starts here
--
for i, k in pairs(headerToAttrList) do
    -- First ensure any client-provided version of this header is removed
    HTTPRequest.removeHeader(i)

    if (Session.containsCredentialAttribute(k.attrName)) then
        local replacementString = nil
        if (k.isMv) then
            -- multi-valued attribute, build a comma-separated string
            -- Note that we pass false for the urlEncodeValues parameter here because in the 
            -- case of this demonstration the values are already url encoded due to the way blueGroups
            -- are established in the credential during SSO.
            replacementString = mvAttrToHTTPHeader(Session.getMvCredentialAttribute(k.attrName), false)
        else
            -- single-valued attribute
            replacementString = urlencode.encode_url(Session.getCredentialAttribute(k.attrName))
        end
        -- Set the replacement string as the header, should already be url-safe encoded
        HTTPRequest.setHeader(i, replacementString)
    end
end

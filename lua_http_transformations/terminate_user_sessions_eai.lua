--[[
        A HTTP transformation that can be used to terminate a specific session, or all sessions for a user. 


        If terminating all sessions for the user, use the AZN_CRED_PRINCIPAL_NAME attribute value as the username to pass. So if the attribute is:
        
        AZN_CRED_PRINCIPAL_NAME	testuser

        Then use: https://webseal.com/terminate/user/testuser


        If terminating a specific session, the value to pass in the URL is the portion of the credential's tagvalue_tagvalue_user_session_id
        attribute AFTER the first underscore. So if the attribute is:
        
        tagvalue_user_session_id	aWFnZGVtby03ZjVkNTdkNzg1LTg3NWxtLWRlZmF1bHQA_aXrZGAAAAAIAAAAsGNl6aUi1A+QBcgAASVZRNFJ4ajZFTnZDb3FpdEkxamdZR3NGOGNnWk13S3dTOFVHaGplQ1ZCVT0=:

        Then use: https://webseal.com/terminate/session/aXrZGAAAAAIAAAAsGNl6aUi1A+QBcgAASVZRNFJ4ajZFTnZDb3FpdEkxamdZR3NGOGNnWk13S3dTOFVHaGplQ1ZCVT0=:

        Requires both http-transformation and eai trigger URL configuration.

        ================

        [http-transformations]
        terminate_user_sessions = terminate_user_sessions.lua

        [http-transformations:terminate_user_sessions]
        request-match = preazn:GET /terminate*

        [eai-trigger-urls]
        trigger = /terminate*

        =============
--]]

local urlencode = require 'urlencode'

function debugLog(s)
   print(s)
--   Control.trace(9, s)
end

function htmlEncode(str)
    if str == nil then
        return nil
    end
    
    -- Replace HTML special characters with their entity equivalents
    local html_entities = {
        ["&"] = "&amp;",
        ["<"] = "&lt;",
        [">"] = "&gt;",
        ['"'] = "&quot;",
        ["'"] = "&#39;"
    }
    
    return (str:gsub("[&<>\"']", html_entities))
end




-- Extract the username or session id from the path
local _,_,username = string.find(HTTPRequest.getURL(), "/terminate/user/(.+)")
local _,_,sessionid = string.find(HTTPRequest.getURL(), "/terminate/session/(.+)")

-- TODO
--   1. For HTTP response header safety and to prevent bad data injection, perform validation on the username and sessionid to ensure only permitted characters are used.
--   2. This should only be accessed and executed by a trusted client. Need to add some way to authenticate clients that are calling this management function.

if (username == nil and sessionid == nil) then
    debugLog("terminate_user_sessions: unable to determine username or session id")
    HTTPResponse.setStatusCode(400)
    HTTPResponse.setStatusMsg("Bad Request")
    HTTPResponse.setBody('<html>Invalid request</html>')
elseif (username ~= nil) then
    debugLog("terminate_user_sessions: terminating sessions for user: " .. username)
    HTTPResponse.setStatusCode(200)
    HTTPResponse.setStatusMsg("OK")
    HTTPResponse.setBody('<html>Deleting sessions for user ... ' .. htmlEncode(username) .. '</html>')
    HTTPResponse.setHeader("am-eai-flags", "stream")
    HTTPResponse.setHeader("am-eai-server-task", "terminate all_sessions " .. username)
elseif (sessionid ~= nil) then
    debugLog("terminate_user_sessions: terminating session id: " .. sessionid)
    HTTPResponse.setStatusCode(200)
    HTTPResponse.setStatusMsg("OK")
    HTTPResponse.setBody('<html>Deleting session id ... ' .. htmlEncode(sessionid) .. '</html>')
    HTTPResponse.setHeader("am-eai-flags", "stream")
    HTTPResponse.setHeader("am-eai-server-task", "terminate session " .. sessionid)
end
Control.responseGenerated(true)


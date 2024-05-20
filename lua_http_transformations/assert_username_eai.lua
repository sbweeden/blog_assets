--[[
        A HTTP transformation that logs you in using the EAI capability as the username provided in the query string.
        
        Definitely for demonstration purposes only!

        Activated in Reverse Proxy config with:

        ================
        [http-transformations]
        assert_username_eai = assert_username_eai.lua

        [http-transformations:assert_username_eai]
        request-match = postazn:GET /assert_username_eai*

        [eai]
        eai-auth = https
        
        [eai-trigger-urls]
        trigger = /assert_username_eai*

        =============

        Also you need to set an unauth acl for the /assert_username_eai so that unauthenticated users can get to it

        The access it with:
        https://webseal.com/assert_username_eai?username=testuser
--]]
local forms = require 'FormsModule'
local logger = require 'LoggingUtils'


local qsParams = forms.getQueryParams(HTTPRequest.getURL())

logger.debugLog(logger.dumpAsString(qsParams));
if qsParams['username'] ~= nil and qsParams['username'] ~= '' then
    -- The "false" here means the ISVA user has to exist in the registry. Set to "true" for external users.
    logger.debugLog("Authenticating as: " .. qsParams['username'])
    Authentication.setUserIdentity(qsParams['username'], false)

    Authentication.setAuthLevel(1)
    -- In this demo assume that /ivcreds is configured to run the cred-viewer local application
    Authentication.setRedirectURL('/ivcreds')
end
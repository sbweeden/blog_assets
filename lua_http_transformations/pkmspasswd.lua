--[[
        A HTTP transformation that can be applied to change password operations
        sent to WRP at /pkmspasswd.form

        Activated in Reverse Proxy config with:

        ================
        [http-transformations]
        pkmspasswd = pkmspasswd.lua

        [http-transformations:pkmspasswd]
        request-match = request:POST /pkmspasswd.form*
        =============
--]]
local forms = require 'FormsModule'
local logger = require 'LoggingUtils'


local formsParams = forms.getPostParams(HTTPRequest.getBody())

logger.debugLog(logger.dumpAsString(formsParams));
if formsParams['old'] ~= nil and formsParams['old'] ~= '' and formsParams['old'] == formsParams['new1'] then
    -- HTTPResponse.setStatusCode(400)
    -- HTTPResponse.setStatusMsg("Bad Request")
    -- HTTPResponse.setBody('<html>Old and new passwords are the same</html>')
    Control.returnErrorPage('Old and new passwords are the same')

    -- Control.responseGenerated(true)
end
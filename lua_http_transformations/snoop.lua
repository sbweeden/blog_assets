--[[
        A HTTP transformation that can be applied to any URL to "snoop" the request or response body

        Activated in Reverse Proxy config with:

        ================
        [http-transformations]
        snoop = snoop.lua

        [http-transformations:snoop]
        request-match = request:POST /mga/sps/oauth/oauth20/token*
        =============
--]]
local logger = require 'LoggingUtils'
logger.debugLog("snoop")
logger.debugLog(Control.dumpContext())
-- Session only available in some phases
if (Control.getStage() ~= "request") then
    logger.debugLog("Session.getSessionId(): " .. logger.dumpAsString(Session.getSessionId()))
    logger.debugLog("Session.getUsername(): " .. logger.dumpAsString(Session.getUsername()))
    logger.debugLog("Session.getSessionAttributeNames(): " .. logger.dumpAsString(Session.getSessionAttributeNames()))
    for _, v in pairs(Session.getSessionAttributeNames()) do
        logger.debugLog("Session.getAttribute(" .. logger.dumpAsString(v) .. "): " .. logger.dumpAsString(Session.getSessionAttribute(v)))
    end
end
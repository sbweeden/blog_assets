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

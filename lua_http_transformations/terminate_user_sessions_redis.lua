--[[
        A HTTP transformation that can be used to terminate all sessions for a user when the WebSEAL or IAG is configured to use Redis for session.

        This rule communicates directly with Redis to delete session keys.

        When terminating all sessions for the user, use the AZN_CRED_PRINCIPAL_NAME attribute value as the username to pass in the URL. So if the attribute is:
        
        AZN_CRED_PRINCIPAL_NAME	testuser

        Then use: https://webseal.com/terminate/user/testuser

        Requires http-transformation configuration shown below:
====== IAG example ==========
policies:

  http_transformations:
    preazn:
      - name: terminate
        paths: 
          - "/terminate*"
        method: "GET"
        rule: "@terminate_user_sessions_redis.lua"
====== END IAG example ==========


====== WebSEAL example ==========
[http-transformations]
terminate_user_sessions = terminate_user_sessions.lua

[http-transformations:terminate_user_sessions]
request-match = preazn:GET /terminate*
====== END WebSEAL example ==========




        This implementation also requires that Redis keys for user sessions are created, which only currently happens if concurrent session
        enforcement is turned on. That means updating your redis configuration to have some kind of (not unlimited) max concurrent sessions.
        The prompt_for_displacement setting is not important, but included for understanding.



====== IAG example ==========
server:
  session:
    redis:
      enabled: true
      concurrent_sessions:
        enabled: true
        prompt_for_displacement: true
        max_user_sessions: 999999
====== End IAG example ==========


====== WebSEAL example ==========
[session]
dsess-server-type = redis
prompt-for-displacement = true
dsess-max-user-sessions = 999999
====== END WebSEAL example ==========

--]]

local urlencode = require 'urlencode'
local logger = require 'LoggingUtils'
local htmlUtils = require 'HTMLUtils'
local redisHelper = require 'RedisHelper'

local function deleteRedisSessions(username)
    logger.debugLog('deleteRedisSessions: attempting delete of all sessions for user: ' .. username)
    local rclient = redisHelper.getRedisClient()

    -- this portion just for debug logging
    local sessionsForUser = redisHelper.getSessionsForUser(rclient, username)
    logger.debugLog('deleteRedisSessions: user: ' .. username .. ' sessions: ' .. logger.dumpAsString(sessionsForUser))

    -- delete all the session
    redisHelper.deleteSessionsForUser(rclient, username)
end

logger.debugLog("terminate_user_sessions on pod: " .. (os.getenv("HOSTNAME") or 'nil') .. ' for URL: ' .. HTTPRequest.getURL())


-- Extract the username from the path /terminate/<username>
local _,_,username = string.find(HTTPRequest.getURL(), "/terminate/user/(.+)")

-- TODO
--   1. To prevent bad data injection, perform validation on the username and sessionid to ensure only permitted characters are used.
--   2. This should only be accessed and executed by a trusted client. Need to add some way to authenticate clients that are calling this management function.

if (username == nil) then
    logger.debugLog("terminate_user_sessions: unable to determine username")
    HTTPResponse.setStatusCode(400)
    HTTPResponse.setStatusMsg("Bad Request")
    HTTPResponse.setBody('<html>Invalid request</html>')
else
    logger.debugLog("terminate_user_sessions: terminating sessions for user: " .. username)
    HTTPResponse.setStatusCode(200)
    HTTPResponse.setStatusMsg("OK")
    HTTPResponse.setBody('<html>Deleting sessions for user ... ' .. htmlUtils.htmlEncode(username) .. '</html>')
    deleteRedisSessions(username)
end
Control.responseGenerated(true)


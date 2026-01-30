--[[
Redis helper for WebSEAL/IAG session management
--]]
local redis = require 'redis'
local logger = require 'LoggingUtils'

local RedisHelper = {}

local REDIS_CONFIG = {
    ["PREFIX"] = "isva-",
    ["HOST"] = "redis",
    ["PORT"] = 6379
}

--
-- Attempt to read updated redis configuration from the WebSEAL configuration file
--
local function readRedisConfig()
    -- try get the PREFIX from the [redis] stanza
    local configuredPrefix = Control.getConfig("redis", "key-prefix")
    if configuredPrefix ~= nil then
        logger.debugLog("readRedisConfig updating PREFIX from WebSEAL config to: " .. configuredPrefix)
        REDIS_CONFIG["PREFIX"] = configuredPrefix
    end

    -- determine default collection name
    local defaultCollectionName = Control.getConfig("redis", "default-collection-name")
    if (defaultCollectionName ~= nil) then
        logger.debugLog("readRedisConfig default-collection-name is: " .. defaultCollectionName)
        -- lookup the collection to find the server entry's name
        local collectionServer = Control.getConfig("redis-collection:" .. defaultCollectionName, "server")
        if (collectionServer ~= nil) then
            logger.debugLog("readRedisConfig server of default collection is: " .. collectionServer)
            -- lookup the server configuration information
            local hostname = Control.getConfig("redis-server:" .. collectionServer, "server")
            if (hostname ~= nil) then
                logger.debugLog("readRedisConfig server hostname is: " .. hostname)
                REDIS_CONFIG["HOST"] = hostname
            end
            local portStr = Control.getConfig("redis-server:" .. collectionServer, "port")
            if (portStr ~= nil) then
                logger.debugLog("readRedisConfig server port is: " .. portStr)
                REDIS_CONFIG["PORT"] = tonumber(portStr)
            end
            local username = Control.getConfig("redis-server:" .. collectionServer, "username")
            if (username ~= nil) then
                logger.debugLog("readRedisConfig username is: " .. username)
                REDIS_CONFIG["USERNAME"] = username
            end
            local password = Control.getConfig("redis-server:" .. collectionServer, "password")
            if (password ~= nil) then
                --logger.debugLog("readRedisConfig password is: " .. password)
                REDIS_CONFIG["PASSWORD"] = password
            end

            -- TODO: Investigate if it is possible to support SSL with this client
        end
    end
    -- this will dump the password if present, so comment out if you don't want that
    logger.debugLog("readRedisConfig - using configuration: " .. logger.dumpAsString(REDIS_CONFIG))
end


function RedisHelper.getRedisClient()
    readRedisConfig()
    local rclient = redis.connect(REDIS_CONFIG["HOST"], REDIS_CONFIG["PORT"])
    if (REDIS_CONFIG["PASSWORD"] ~= nil) then
        if (REDIS_CONFIG["USERNAME"] ~= nil) then
            rclient:auth(REDIS_CONFIG["USERNAME"], REDIS_CONFIG["PASSWORD"])
        else
            rclient:auth(REDIS_CONFIG["PASSWORD"])
        end
    end
    return rclient
end

local function getUserSessionsKey(username)
    -- username keys are lowercase in redis
    return REDIS_CONFIG["PREFIX"] .. "user-" .. string.lower(username)
end    

-- Looks up the (REDIS_CONFIG["PREFIX"] + user-<username>) key and returns an array of all members or nil if empty or not present
function RedisHelper.getSessionsForUser(client, username)
    if username == nil then
        return nil
    end

    return client:smembers(getUserSessionsKey(username))
end

function RedisHelper.deleteSessionByID(client, sessionID)
    local sessionHashEntryName = REDIS_CONFIG["PREFIX"] .. "session-" .. sessionID
    local clientsSetName = REDIS_CONFIG["PREFIX"] .. "client-" .. sessionHashEntryName

    logger.debugLog("Deleting session hash entry: " .. sessionHashEntryName)
    client:del(sessionHashEntryName)
    logger.debugLog("Deleting clients set: " .. clientsSetName)
    client:del(clientsSetName)
end

local function escape_pattern(text)
  -- Replaces all non-alphanumeric characters (%w) with a '%' followed by the character itself ( %1 or %0)
  return (text:gsub("([^%w])", "%%%1"))
end

function RedisHelper.deleteSessionsForUser(client, username)
    -- get existing sessions
    local currentUserSessions = RedisHelper.getSessionsForUser(client, username)
    if (currentUserSessions ~= nil and #currentUserSessions > 0) then
        for i,v in ipairs(currentUserSessions) do
            -- determine the sessionID from the entry
            local sidRegexp = escape_pattern(REDIS_CONFIG["PREFIX"] .. "session-") .. "(.+)"
            local sessionID = string.match(v, sidRegexp)
            logger.debugLog("RedisHelper.deleteSessionsForUser sidRegexp= " .. sidRegexp .. "v=" .. v .. " sessionID: " .. (sessionID or 'nil'))
            if (sessionID ~= nil) then
                -- delete this sessions keys
                RedisHelper.deleteSessionByID(client, sessionID)
            end
        end

        -- now delete the user sessions entry
        client:del(getUserSessionsKey(username))
    end
end

return RedisHelper
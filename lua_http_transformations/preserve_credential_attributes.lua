--[[
        A transformation that runs at the conclusion of each authentication method that it is configured
        against to propagate forward a set of credential attributes during stepup operations.

        The way this works is that either an encrypted cookie, or a session memory cache is used to collect
        and update the attributes to preserve at the conclusion of each authentication method.

        Update the list of attributes you want to preserve below in the ATTR_NAMES variable.

        
        It is populated cumulatively at the end of every mechanism in a postauthn transformation.
        There is no pruning of attributes at any stage.
        At the end of each authentication method, any attributes that are in the preserve list are
        added back in. There are merge strategies for attributes that are present in both the 
        preserve list and the stepup credential. Normally I think you would want the "add" or
        "replace" strategies.

        NOTE: To use this transformation rule with server-side session state as the location to remember
        the attributes to preserve during stepup, a fix is required for WebSEAL such that the Session 
        id information is made available to postauthn transformation rules. Without that fix, 
        STATE_STORAGE_STRATEGY="session" will not work.
        There is trace at the start of the rule that will print out if the rule detects you are running
        on a version of WebSEAL that does not have the fix and you are using "session" storage strategy.


        Activated in Reverse Proxy config with:

        ================
        [http-transformations]
        preserve_credential_attributes = preserve_credential_attributes.lua

        # Add/remove request-match lines for each type of authentication mechanism you 
        # have in your WebSEAL.
        [http-transformations:preserve_credential_attributes]
        request-match = postauthn:ssl
        request-match = postauthn:password
        request-match = postauthn:ext-auth-interface


        # Don't forget to inject your own shared secret to be used for the cookie encryption/decryption
        [http-transformations:secrets]
        STATE_COOKIE_SHARED_SECRET=MySecureKey123!@#$%^&*()_+=-


        =============		
--]]

local cjson = require "cjson"
local logger = require "LoggingUtils"
local cryptoLite = require "CryptoLite"

-- list of attribute names that we want to preserve through stepup operations
-- There is no significance to these defaults - it's just a placehoder 
-- that I was testing with, so delete/replace it with whatever attributes you care about.
local ATTR_NAMES = { "method", "serial-number" }

-- MERGE_STRATEGY determines whether to add, keep, or replace an attribute 
-- in the memory cache with any that appears in "current" credential after 
-- a stepup has occured. This might result in multi-valued attributes in the cred
-- if any of the attrs in ATTR_NAMES is already multi-valued, or if using the 
-- "add" merge strategy and an attributes value changes between login methods.
-- In this implementation, the same merge strategy applies to all attributes.

-- the value should be one of "add", "keep", "replace"
local MERGE_STRATEGY = "add"

-- name of session attribute or cookie name that stores the JSON of the table of 
-- attributes we are preserving through stepup operations
local SESSION_ATTROBJ_NAME = "PRESERVE_SESSION_ATTRIBUTES"

--
-- One of "session", "cookie"
-- The "session" option requires an update to WebSEAL that you may or may not have.
-- If you do not, then an error will be printed to trace. 
--
local STATE_STORAGE_STRATEGY="cookie"

--
-- Only used if STATE_STORAGE_STRATEGY is "cookie"
-- do not use STATE_COOKIE_GENERATION_VERSION=1 for production - it is for development testing / visual inspection only
-- always use version 2 (shared secret encrption of a JSON string)
--
local STATE_COOKIE_GENERATION_VERSION=2
--local STATE_COOKIE_VALID_VERSIONS={1,2}
local STATE_COOKIE_VALID_VERSIONS={2}

-- It is expected that step-up occurs within this amount of seconds since the last authentication
-- To disable this check, set to -1
local MAX_COOKIE_AGE_SECONDS=-1

-- read this from configuration file
-- local STATE_COOKIE_SHARED_SECRET="MySecureKey123!@#$%^&*()_+=-"
local STATE_COOKIE_SHARED_SECRET=Control.getConfig("http-transformations:secrets", "STATE_COOKIE_SHARED_SECRET")

-- We also decide whether or not to check that the stepup user is the same as the original user based on existing WebSEAL config
local configStr = Control.getConfig("step-up", "verify-step-up-user")
local VERIFY_STEPUP_USER=(configStr ~= nil and (string.lower(configStr) == "true" or string.lower(configStr) == "yes"))





--[[
START UTILITY FUNCTIONS
--]]


local function getCurrentUsername()
    local username = Session.getCredentialAttribute("AZN_CRED_PRINCIPAL_NAME")
    return username
end


--[[
Checks if an array has a value
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
Retrieves a table of attributes we are preserving through a stepup operation, or establishes an empty list if none.
If validation of any existing attribute storage fails, then a new empty list is returned.
--]]

local function getSessionAttrsObj()

    local sessionAttrObjStr = nil

    -- this is the preferred approach, however Session currently not available in postauthn mapping rule
    if (STATE_STORAGE_STRATEGY == "session") then
        sessionAttrObjStr = (Session.getSessionAttribute(SESSION_ATTROBJ_NAME) or "{}")
    else
        -- alternative approach: uses an encrypted data structure, tranformed into a string and stored as a cookie
        -- the data structure contains expiry and subject attributes to ensure it is short-lived and is not used
        -- by a user other than the one for which it was created if verify-step-user is true in WebSEAL
        sessionAttrObjStr = "{}"
        local cookieStrValue = HTTPRequest.getCookie(SESSION_ATTROBJ_NAME)
        if (cookieStrValue ~= nil) then
            -- the cookie string value is of the format version_label:value where version_label allows us to
            -- define, identify and support different formats should they change over time. Here we use
            -- a regex match to extract the version label (integer) and the actual value.
            local versionLabel, value = cookieStrValue:match("^(%d+):(.+)$")
            if (versionLabel ~= nil and hasValue(STATE_COOKIE_VALID_VERSIONS, tonumber(versionLabel)) and value ~= nil) then
                if (versionLabel == "1") then
                    -- never actually use this version in production as its completely insecure. Just for testing purposes.
                    sessionAttrObjStr = value
                elseif (versionLabel == "2") then
                    -- value should be a symmetrically encrypted string
                    local success, jsonStr = pcall(cryptoLite.decryptSymmetric, value, STATE_COOKIE_SHARED_SECRET)
                    if (success) then
                        local stateJSON = cjson.decode(jsonStr)

                        --logger.debugLog("stateJSON is: " .. cjson.encode(stateJSON))
                    
                        --
                        -- validation checks of the stateJSON fields
                        -- 
                        local valid = true

                        -- check expiry if present
                        if (valid and stateJSON["exp"] ~= nil) then
                            local nowSec = math.floor(os.time())
                            local expSec = math.floor(stateJSON["exp"])
                            logger.debugLog("Checking expiry time. Now: " .. nowSec .. " cookie exp: " .. expSec .. " remaining: " .. (expSec - nowSec))
                            if (nowSec > expSec) then
                                valid = false
                                logger.debugLog("Cookie value has expired")
                            end
                        end

                        -- if sub is present, check that it matches the current username
                        if (valid and stateJSON["sub"] ~= nil) then
                            if (stateJSON["sub"] ~= getCurrentUsername()) then
                                valid = false
                                logger.debugLog("Cookie value has incorrect sub field")
                            end
                        end

                        if (valid) then
                            -- all good, consume the attrsObj field from stateJSON
                            sessionAttrObjStr = cjson.encode(stateJSON["attrsObj"])
                        end
                    else
                        logger.debugLog("Failed to decrypt cookie value: " .. value)
                    end
                else
                    logger.debugLog("Cookie value version not implemented:" .. versionLabel)
                end
            else
                logger.debugLog("Cookie value is not in the expected format. versionLabel: " .. (versionLabel or 'nil') .. " value: " .. (value or 'nil'))
            end
        else
            logger.debugLog("Cookie not found: " .. SESSION_ATTROBJ_NAME)
        end
    end

    return cjson.decode(sessionAttrObjStr)
end

--[[
Saves a list of attributes that we plan to propagate through stepup authentication.
--]]
local function saveSessionAttrsObj(o)

    if (STATE_STORAGE_STRATEGY == "session") then
        -- this is the preferred approach, however Session currently not available in postauthn mapping rule
        Session.setSessionAttribute(SESSION_ATTROBJ_NAME, cjson.encode(o))
    else
        -- alternative approach: uses an encrypted data structure, tranformed into a string and stored as a cookie
        -- the data structure contains expiry and subject attributes to ensure it is short-lived and is not used
        -- by a user other than the one for which it was created if verify-step-user is true in WebSEAL
        local cookieValue = nil
        if (STATE_COOKIE_GENERATION_VERSION == 1) then
            -- never actually use this version in production as its completely insecure. Just for testing purposes.
            cookieValue = "1:" .. cjson.encode(o)
        elseif (STATE_COOKIE_GENERATION_VERSION == 2) then

            local stateJSON = {}
            stateJSON["attrsObj"] = o

            -- if we are enforcing that the stepup username must be the same as the current username then insert the sub
            if (VERIFY_STEPUP_USER) then
                stateJSON["sub"] = getCurrentUsername()
            end

            -- insert expiry time if we are enforcing a max age
            if (MAX_COOKIE_AGE_SECONDS > 0) then
                expireAtSeconds = math.floor(os.time() + MAX_COOKIE_AGE_SECONDS)
                stateJSON["exp"] = expireAtSeconds
            end

            -- build the version 2 cookie value
            cookieValue = "2:" .. cryptoLite.encryptSymmetric(cjson.encode(stateJSON), STATE_COOKIE_SHARED_SECRET)
        else
            -- should not happen - means a development error or misconfiguration
            logger.debugLog("Cookie version not yet supported")
        end

        -- add appropriate cookie attributes and set it on the response
        local cookieValueStr = cookieValue .. ";path=/;Secure;HttpOnly"

        -- Commented out since I don't think we shoud expire the cookie - just leave it as a 
        -- session cookie since expiry is enforced at the application data level anyway.
        --if (MAX_COOKIE_AGE_SECONDS > 0) then
        --    cookieValueStr = cookieValueStr .. ";max-age=" .. MAX_COOKIE_AGE_SECONDS
        --end

        HTTPResponse.setCookie(SESSION_ATTROBJ_NAME, cookieValueStr)
    end
end

--[[
Works around an issue where the IVIA Session apis that return an "array" are not correctly indexed from 1.
The problem is that you cannot call ipairs on those arrays as the 0-index first element will be skipped.
This rebuilds the table representing the array from 0-indexed to 1-indexed, in such a way that when the
issue is fixed in IVIA, this code will continue to work without breaking anything.

It does this by taking all the indexes that are in tab, sorting them, then constructing a new table
with the values from tab in the sorted order of whatever their original indexes were.
--]]
local function fixArray(tab)
    -- sort the existing indexes of tab, which may be 0-based, or 1-based, or based on any other sortable sequence
    local indexes = {}
    for i,v in pairs(tab) do
        table.insert(indexes, i)
    end
    table.sort(indexes)

    -- iterate over the sorted indexes, and build a new properly 1-indexed table as the resulting array
    local result = {}
    for i,v in ipairs(indexes) do
        table.insert(result, tab[v])
    end
    return result
end

--[[
END UTILITY FUNCTIONS
--]]


--[[
START MAIN ENTRY POINT
--]]



logger.debugLog("preserve_credential_attributes called during stage: " .. Control.getStage())
if (Control.getStage() == "postauthn") then
    -- detect if WebSEAL has the fix for making the Session available to the postauthn transformation state
    if (STATE_STORAGE_STRATEGY == "session" and Session.getSessionId() == nil) then
        logger.debugLog("preserve_credential_attributes: ******** ERROR: The version of WebSEAL you are running needs a fix to make the Session information available to the postauthn Lua transformation stage")
    else
        logger.debugLog("preserve_credential_attributes.AZN_CRED_AUTH_METHOD: " .. Session.getCredentialAttribute("AZN_CRED_AUTH_METHOD"))

        -- first lets update the memory cache with any attribute values that are 
        -- currently in the credential after this authentication mechanism has run
        local attrsObj = getSessionAttrsObj()
        logger.debugLog("preserve_credential_attributes starting attrsObj: " .. cjson.encode(attrsObj))
        logger.debugLog(Control.dumpContext())

        for i,v in ipairs(ATTR_NAMES) do
            -- we only have something to look at if the credential contains one or more values for this attribute
            if (Session.containsCredentialAttribute(v)) then

                local valuesArray = fixArray(Session.getMvCredentialAttribute(v))

                if (MERGE_STRATEGY == "replace") then
                    -- if the merge strategy is replace then just set the memory values to that of the credential
                    attrsObj[v] = valuesArray
                elseif (MERGE_STRATEGY == "keep") then
                    -- they get added to the memory cache only if the memory cache does not already have a value for this attribute
                    if (attrsObj[v] == nil) then
                        --logger.debugLog("preserve_credential_attributes establishing memory cache for attr: " .. v .. " with value: " .. logger.dumpAsString(Session.getMvCredentialAttribute(v)))
                        attrsObj[v] = valuesArray
                    end
                else
                    -- merge strategy is add - either establish entry in memory cache or add any new values to the existing list (that are not already present)
                    if (attrsObj[v] == nil) then
                        logger.debugLog("preserve_credential_attributes establishing memory cache for attr: " .. v .. " with value: " .. logger.dumpAsString(valuesArray))
                        attrsObj[v] = valuesArray
                    else
                        --logger.debugLog("preserve_credential_attributes merging memory cache for attr: " .. v .. " with value: " .. logger.dumpAsString(attrsObj[v]) .. " and current credential values: " .. logger.dumpAsString(valuesArray))
                        local currentValues = attrsObj[v]
                        for i2,v2 in ipairs(valuesArray) do
                            if (not hasValue(currentValues, v2)) then
                                table.insert(currentValues, v2)
                            end
                        end
                        attrsObj[v] = currentValues
                        logger.debugLog("preserve_credential_attributes merged memory cache for attr: " .. v .. " is: " .. logger.dumpAsString(attrsObj[v]))
                    end
                end
            end
        end

        -- store whatever we ended up with in the session memory
        logger.debugLog("preserve_credential_attributes ending attrsObj: " .. cjson.encode(attrsObj))
        saveSessionAttrsObj(attrsObj)

        -- set all the attrs in attrsObj in the credential
        for k,v in pairs(attrsObj) do
            Session.setCredentialAttribute(k,v)
        end
    end
end

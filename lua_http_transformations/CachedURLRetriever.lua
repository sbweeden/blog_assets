--[[
Caches retrieved URL bodies
--]]
local cjson = require 'cjson'
local httpreq = require 'http.request'
local httpcookie = require 'http.cookie'
local httpheaders = require 'http.headers'
local httputil = require 'http.util'
local tls = require 'http.tls'
local logger = require 'LoggingUtils'

local CachedURLRetriever = {}

local urlCache = nil

function CachedURLRetriever.getURL(url, options)
    local resultStr = nil
    if not urlCache then
        urlCache = cjson.decode('{}')
    end

    resultStr = urlCache[url]
    if (not resultStr or (options and options["ignoreCache"])) then
        -- need to retrieve it
        --logger.debugLog("CachedURLRetriever.getURL: retrieving content for URL: " .. url)
        local req = httpreq.new_from_uri(url)

        --
        -- Use a new cookie store each time - we want our requests to be stateless and 
        -- unrelated to any other invocations.
        -- see: https://daurnimator.github.io/lua-http/0.3/#http.request.cookie_store
        -- NOTE WELL: defaults to a shared store.
        --
        local newCookieStore = httpcookie.new_store()	
        req.cookie_store = newCookieStore
        
        -- update request HTTP headers - note this is always a GET request
        -- note use of upsert here (rather than append) to replace any defaults
        req.headers:upsert(":method", "GET")
        if (options and options.headers) then
            for n,v in pairs(options.headers) do
                req.headers:upsert(n, v)
            end
        end

        -- we are going to use TLS	
        req.ctx = tls.new_client_context()
        
        -- ignore SSL cert errors - risky, don't do it unless you have to
        if (options and options.skipTLSVerify) then
            req.ctx:setVerify(require "openssl.ssl.context".VERIFY_NONE)
        end
        
        local headers, stream = assert(req:go())
        
        local httpStatusCode = headers:get ":status"
        -- logger.debugLog("CachedURLRetriever.getURL HTTP response status: " .. httpStatusCode)
        if httpStatusCode == "200" then
            local rspbody = assert(stream:get_body_as_string())
            if not (rspbody == nil or (not rspbody)) then
                urlCache[url] = rspbody
                resultStr = rspbody
            else
                logger.debugLog("CachedURLRetriever.getURL: no body in HTTP response")
            end
        else
            logger.debugLog("CachedURLRetriever.getURL: invalid HTTP response code: " .. httpStatusCode)
        end        
    end

    local result = resultStr
    if (resultStr and options and options.returnAsJSON) then
        result = cjson.decode(resultStr)
    end
    return result
end

return CachedURLRetriever
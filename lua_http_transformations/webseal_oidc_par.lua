--[[
        A HTTP transformation that can be used as an alternative kickoff URL for OIDC to perform pushed authorization requests (PAR)
        according to:

        https://datatracker.ietf.org/doc/html/rfc9126

        Activated in Reverse Proxy config with:

        ================
        [http-transformations]
        webseal_oidc_par = webseal_oidc_par.lua

        [http-transformations:webseal_oidc_par]
        request-match = preazn:GET /oidckickoff*
        =============
--]]
local cjson = require 'cjson'
local baseutils = require 'basexx'
local httpreq = require 'http.request'
local httpcookie = require 'http.cookie'
local httpheaders = require 'http.headers'
local httputil = require 'http.util'
local tls = require 'http.tls'

local logger = require 'LoggingUtils'
local formsModule = require 'FormsModule'

local WEBSEAL_SESSION_COOKIE_NAME = Control.getConfig("session", "ssl-session-cookie-name")

local OP_DISCOVERY_ENDPOINT=Control.getConfig("oidc:default", "discovery-endpoint")
local CLIENT_ID=Control.getConfig("oidc:default", "client-id")
local CLIENT_SECRET=Control.getConfig("oidc:default", "client-secret")
local REDIRECT_URL = "https://" .. Control.getConfig("oidc:default", "redirect-uri-host") .. "/pkmsoidc"

local SELF_WEBSEAL_OIDC_KICKOFF_URL=REDIRECT_URL .. "?iss=default"

function performOIDCDiscovery()
        local result = nil

        -- really import - make sure we do not use the shared cookie store for these requests
        -- see: https://daurnimator.github.io/lua-http/0.3/#http.request.cookie_store
        -- NOTE WELL: defaults to a shared store.
        local newCookieStore = httpcookie.new_store()

        local req = httpreq.new_from_uri(OP_DISCOVERY_ENDPOINT)
        req.cookie_store = newCookieStore

        -- update request HTTP headers
        -- note use of upsert here (rather than append) to replace any defaults
        req.headers:upsert("accept", "application/json")
        req.headers:upsert(":method", "GET")


        -- we are going to use TLS	
        req.ctx = tls.new_client_context()

        -- ignore SSL cert errors - bit sketchy, but better than having to figure out the localhost certificate for the runtime
        req.ctx:setVerify(require "openssl.ssl.context".VERIFY_NONE)

        local headers, stream = assert(req:go())

        local httpStatusCode = headers:get ":status"
        logger.debugLog("performOIDCDiscovery HTTP response status: " .. httpStatusCode)
        if httpStatusCode == "200" then
                local rspbody = assert(stream:get_body_as_string())
                if not (rspbody == nil or (not rspbody)) then
                        result = cjson.decode(rspbody)
                else
                        logger.debugLog("performOIDCDiscovery: no body in HTTP response")
                end
        else
                logger.debugLog("performOIDCDiscovery: invalid HTTP response code: " .. httpStatusCode)
        end

        return result
end

function parRequest(oidcDiscoveryDocument, oidcRedirectURL)
        local result = nil

        -- split the redirect URL into its components
        -- example oidcRedirectURL
        -- https://myidp.ice.ibmcloud.com/oauth2/authorize?
        --    scope=openid&
        --    response_type=code&
        --    client_id=00ffd65f-25f3-4d62-ae7e-6f6ba0445543&
        --    redirect_uri=https://mybox33.asuscomm.com:30443/pkmsoidc&
        --    state=24b9bc15-b46a-3581-802c-fd02cb883878&
        --    nonce=55289592-8347-69c4-80a7-0674bbef6c89&
        --    code_challenge=G4Hns2r1uf3IfvwOrPaQZZISej4YIvNcyKf6cMqYhuU&
        --    code_challenge_method=S256
        --    
        
        local _,_,redirURL = string.find(oidcRedirectURL, "(.+)%?")
        logger.debugLog("parRequest: oidcRedirectURL: " .. oidcRedirectURL)
        logger.debugLog("parRequest: redirURL: " .. (redirURL ~= nil and redirURL or 'nil'))
        local aznParams = formsModule.getQueryParams(oidcRedirectURL) 

        -- really import - make sure we do not use the shared cookie store for these requests
        -- see: https://daurnimator.github.io/lua-http/0.3/#http.request.cookie_store
        -- NOTE WELL: defaults to a shared store.
        local newCookieStore = httpcookie.new_store()

        local req = httpreq.new_from_uri(oidcDiscoveryDocument.pushed_authorization_request_endpoint)
        req.cookie_store = newCookieStore

        -- update request HTTP headers
        -- note use of upsert here (rather than append) to replace any defaults
        req.headers:upsert("authorization", "Basic " .. baseutils.to_base64(CLIENT_ID .. ':' .. CLIENT_SECRET))
        req.headers:upsert("content-type", "application/x-www-form-urlencoded")
        req.headers:upsert("accept", "application/json")
        req.headers:upsert(":method", "POST")

        -- set post body params
        local body = formsModule.getPostBody(aznParams)
	req:set_body(body)


        -- we are going to use TLS	
        req.ctx = tls.new_client_context()

        -- ignore SSL cert errors - bit sketchy, but better than having to figure out the localhost certificate for the runtime
        req.ctx:setVerify(require "openssl.ssl.context".VERIFY_NONE)

        local headers, stream = assert(req:go())

        local httpStatusCode = headers:get ":status"
        logger.debugLog("parRequest HTTP response status: " .. httpStatusCode)
        if httpStatusCode == "201" then
                local rspbody = assert(stream:get_body_as_string())
                if not (rspbody == nil or (not rspbody)) then
                        -- example: {"request_uri":"urn:ietf:params:oauth:request_uri:09NMA6BTuC463c-7r0f82rF9puJTfoNl6DqJVitKf8g","expires_in":600}
                        local parResponse = cjson.decode(rspbody)
                        local newAznParams = {}
                        newAznParams["request_uri"] = parResponse["request_uri"]
                        newAznParams["client_id"] = aznParams["client_id"]
                        result = redirURL .. "?" .. formsModule.getPostBody(newAznParams)
                else
                        logger.debugLog("parRequest: no body in HTTP response")
                end
        else
                logger.debugLog("parRequest: invalid HTTP response code: " .. httpStatusCode)
        end
        return result
end

function oidcKickoff()
        local result = nil

        logger.debugLog("oidcKickoff: performing GET request to: " .. SELF_WEBSEAL_OIDC_KICKOFF_URL)

        -- really import - make sure we do not use the shared cookie store for these requests
        -- see: https://daurnimator.github.io/lua-http/0.3/#http.request.cookie_store
        -- NOTE WELL: defaults to a shared store.
        local newCookieStore = httpcookie.new_store()

        local req = httpreq.new_from_uri(SELF_WEBSEAL_OIDC_KICKOFF_URL)
        req.cookie_store = newCookieStore

        -- because we are expecting a 302 that we want to capture
        req.follow_redirects = false

        -- update request HTTP headers
        -- note use of upsert here (rather than append) to replace any defaults
        req.headers:upsert("accept", "*/*")

        -- We MUST already have a session. This request has to be on the same session so that the state_id is
        -- bound to the same session on redirect from the OP. Therefore re-use the session cookie in this request.
        -- 
        req.headers:upsert("Cookie", "PD-S-SESSION-ID=" .. HTTPRequest.getCookie(WEBSEAL_SESSION_COOKIE_NAME))

        -- we are going to use TLS	
        req.ctx = tls.new_client_context()

        -- ignore SSL cert errors - bit sketchy, but better than having to figure out the localhost certificate for the runtime
        req.ctx:setVerify(require "openssl.ssl.context".VERIFY_NONE)

        local headers, stream = assert(req:go())

        local httpStatusCode = headers:get ":status"
        logger.debugLog("parRequest HTTP response status: " .. httpStatusCode)
        if httpStatusCode == "302" then
                result = headers:get "location"
        else
                logger.debugLog("oidcKickoff: invalid HTTP response code: " .. httpStatusCode)
        end
        return result
end

-- if there is no current PD-S-SESSION-ID cookie, then redirect back to ourselves to get one
if (HTTPRequest.getCookie(WEBSEAL_SESSION_COOKIE_NAME) == nil) then
        logger.debugLog("webseal_oidc_par: performing one-time redirect to self to get session cookie")
        HTTPResponse.setStatusCode(302)
        HTTPResponse.setStatusMsg("Found")
        HTTPResponse.setHeader("Location", HTTPRequest.getURL())
        HTTPResponse.setBody('<html>Redirecting to self...</html>')
        Control.responseGenerated(true)
else
        local error = nil
        local oidcRedirectURL = nil

        -- normal processing
        local oidcDiscoveryDocument = performOIDCDiscovery(OP_DISCOVERY_ENDPOINT)
        if (oidcDiscoveryDocument == nil) then
                error = "Unable to perform OIDC discovery"
        end

        if (error == nil) then
                oidcRedirectURL = oidcKickoff()
                if (oidcRedirectURL == nil) then
                        error = "Unable to perform OIDC kickoff"
                end
        end

        if (error == nil) then
                oidcRedirectURL = parRequest(oidcDiscoveryDocument, oidcRedirectURL)
                if (oidcRedirectURL == nil) then
                        error = "Unable to perform PAR request"
                end
        end

        if (error == nil) then
                -- now redirect to the real OP with the client_id and request_uri only
                HTTPResponse.setStatusCode(302)
                HTTPResponse.setStatusMsg("Found")
                HTTPResponse.setHeader("Location", oidcRedirectURL)
                HTTPResponse.setBody('<html>Redirecting to OP...</html>')
        else
                HTTPResponse.setStatusCode(400)
                HTTPResponse.setStatusMsg("Bad request")
                HTTPResponse.setBody('<html>'..error..'</html>')
        end
        Control.responseGenerated(true)
end
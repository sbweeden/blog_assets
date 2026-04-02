--[[
        A HTTP transformation that can act as an OIDC client instead of using the built-in WebSEAL/IAG OIDC client.

        Requires configuration as described below:

        For OIDC kickoff, in IAG you can use auth_challenge_redirect:
====== IAG example ==========
identity:
  auth_challenge_redirect:
    url: /oidckickoff?issuer=myidp_plain

====== END IAG example ==========

        In WebSEAL you could use local-response-redirect, or customize the login page to redirect to the kickoff url. 
        This example shows local-response-redirect:
====== WebSEAL example ==========
[acnt-mgt]
enable-local-response-redirect = yes

[local-response-redirect]
local-response-redirect-uri = [login] /oidckickoff?issuer=myidp_plain
====== END WebSEAL example ==========


        For HTTP transformation policies:

====== IAG example ==========
policies:

  http_transformations:
    request:
      - name: jwks
        paths:
          - "/oidcjwks"
        method: "GET"
        rule: "@oidcclient.lua"
    preazn:
      - name: oidcclient_kickoff
        paths: 
          - "/oidckickoff*"
        method: "GET"
        rule: "@oidcclient.lua"
      - name: oidcclient_slo_post
        paths: 
          - "/oidcslo/*"
        method: "POST"
        rule: "@oidcclient.lua"
      - name: oidcclient_slo_get
        paths: 
          - "/oidcslo"
        method: "GET"
        rule: "@oidcclient.lua"
    - name: OPTIONAL_sampleresourcerequest
        paths: 
          - "/sampleresourcerequest"
        method: "GET"
        rule: "@oidcclient.lua"
    postazn:
      - name: oidcclient_redirect_get
        paths: 
          - "/oidcredirect/*"
        method: "GET"
        rule: "@oidcclient.lua"
      - name: oidcclient_redirect_post
        paths: 
          - "/oidcredirect/*"
        method: "POST"
        rule: "@oidcclient.lua"
====== END IAG example ==========


====== WebSEAL example ==========
[http-transformations]
oidcclient = oidcclient.lua

[http-transformations:oidcclient]
request-match = request:GET /oidcjwks *
request-match = preazn:GET /oidckickoff*
# next is just for testing
request-match = preazn:GET /sampleresourcerequest *
request-match = postazn:GET /oidcredirect/*
request-match = postazn:POST /oidcredirect/*
====== END WebSEAL example ==========

Additionally requires that the redirect URL path be configured as an EAI trigger URL:

====== IAG example ==========
identity:
  eai:
    triggers:
      - /oidcredirect/*
====== END IAG example ==========
[eai]
eai-auth = https

[eai-trigger-urls]
trigger = /oidcredirect/*
====== WebSEAL example ==========

====== END WebSEAL example ==========

Additionally, an unauthenticated allowed policy has to be associated with both the kickoff and redirect paths. 
In IAG config this might look like:

policies:
  authorization:
    - name: unauth_allowed
      paths: 
        - "/oidckickoff*"
        - "/oidcredirect/*"
        - "/oidcslo/*"
      rule: anyuser
      action: permit

Finally, since we store session information in unauthenticated sessions, these need to be turned on:

In IAG:

advanced:
  configuration:
    - stanza: session
      entry: create-unauth-sessions
      operation: set
      value:
        - "yes"

In WebSEAL:
[session]
create-unauth-sessions = yes

--]]

local baseutils = require 'basexx'
local cjson = require 'cjson'
local httpreq = require 'http.request'
local httpcookie = require 'http.cookie'
local httpheaders = require 'http.headers'
local httputil = require 'http.util'
local tls = require 'http.tls'
local logger = require 'LoggingUtils'
local formsModule = require 'FormsModule'
local cachedURLRetriever = require 'CachedURLRetriever'
local cryptoLite = require 'CryptoLite'
local jwtUtils = require 'JWTUtils'
local htmlUtils = require 'HTMLUtils'
local redisHelper = require 'RedisHelper'

--[[
        Config
--]]

--logger.debugLog("oidcclient enter")

local redisClient = nil

-- Note: You can (and should) make this a HTTP transformation secret in configuration. This might be a Kubernetes secret in container deployment.
--local clientConfigString = os.getenv("CLIENT_CONFIG_JSON")
local clientConfigString = [[
{
    "default_issuer": "myidp_dpop",
    "issuers": {
        "myidp_dpop": {
            "op_issuer_uri": "https://REDACTED/oauth2",
            "client_id": "REDACTED",
            "client_secret": "REDACTED",
            "dpop_signing_alg": "ES256",
            "skipTLSVerify": false,
            "preferred_client_auth_method": "private_key_jwt",
            "prefer_pushed_authorization_requests": true,
            "jwkPrivateKey": {"alg":"ES256","kty":"EC","crv":"P-256","y":"sPH2ogR_gNDoYzVk6EiEpSM4l3phFYqhtYLTLy9S2C4","d":"pAeYfDXW1lyFul5wwQGcteIA0jdeg6ZoINkxELMZPCY","x":"-SP-kbAdg3AwSjqE4-jYLpY9rBSUvNWnT7fwa67pr4I"},
            "jwkPublicKey": {"alg":"ES256","x":"-SP-kbAdg3AwSjqE4-jYLpY9rBSUvNWnT7fwa67pr4I","y":"sPH2ogR_gNDoYzVk6EiEpSM4l3phFYqhtYLTLy9S2C4","kty":"EC","crv":"P-256"}
        },
        "myidp_plain": {
            "op_issuer_uri": "https://REDACTED/oidc/endpoint/default",
            "client_id": "REDACTED",
            "client_secret": "REDACTED",
            "skipTLSVerify": false,
            "preferred_client_auth_method": "client_secret_post",
            "prefer_pushed_authorization_requests": true
        }

    }
}
]]


local oidcClientConfig = cjson.decode(clientConfigString)

local MAX_SESSION_LIFETIME = 3600
-- now try to read it from config
local sessionTimeoutStr = Control.getConfig("session", "timeout")
if sessionTimeoutStr ~= nil then
    MAX_SESSION_LIFETIME = tonumber(sessionTimeoutStr)
end
--logger.debugLog("MAX_SESSION_LIFETIME: " .. logger.dumpAsString(MAX_SESSION_LIFETIME))



--[[
        Utility Functions
--]]

--[[
    computeLeftMostHash
    Returns base64url encoded left-most half of the sha256 hash of the data
-- ]]

function computeLeftMostHash(data)
    local fullHashb64u = cryptoLite.sha256(data)
    local fullHash = baseutils.from_url64(fullHashb64u)
    local leftMostHash = string.sub(fullHash, 1, (#fullHash / 2))
    return baseutils.to_url64(leftMostHash)
end

--[[
    hasValue
    determine if table has value
-- ]]
local function hasValue(t, v)
    for i, value in ipairs(t) do
        if (value == v) then
            return true
        end
    end
    return false
end

--[[
    isArray
    determine if table looks like an array
-- ]]
function isArray(t)
    if type(t) ~= "table" then 
        return false 
    end
    local count = 0
    for k, v in pairs(t) do
        if type(k) ~= "number" or k < 1 or math.floor(k) ~= k then
            return false
        end
        count = count + 1
    end
    for i = 1, count do
        if t[i] == nil then 
            return false 
        end
    end
    return true
end

--[[
    getBaseURL
    determines the base URL for the request
-- ]]
local function getBaseURL()
    return "https://" .. HTTPRequest.getHeader("host")
end


--[[
    generateRandomString
    generates a random string of given length from given (or default) character pool 
    for example used for pkce code challenge
-- ]]
local function generateRandomString(length, char_pool)
    -- Default to an alphanumeric character set if none is provided
    char_pool = char_pool or "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
    local pool_length = #char_pool
    local result = {} -- Use a table to efficiently build the string

    for i = 1, length do
        -- Generate a random index within the character pool range [1, pool_length]
        local random_index = math.random(1, pool_length)
        -- Extract the character at the random index
        local random_char = string.sub(char_pool, random_index, random_index)
        -- Add the character to the result table
        result[i] = random_char
    end

    -- Concatenate all characters in the table into a single string
    return table.concat(result)
end

--[[
    errorResponseHTML
    Use for returning a HTML error page to the browser, using statusCode (optional) or defaulting to 400
--]]
local function errorResponseHTML(msg, statusCode)
	htmlContent = [[
<html>
<head>
<style>
.octagonWrap {
    width:500px;
    height:500px;
    float: left;
    position: relative;
    overflow: hidden;
}
.octagon {
    position: absolute;
    top: 0; right: 0; bottom: 0; left: 0;
    overflow: hidden;
    transform: rotate(45deg);
    background: red;
    border: 3px solid black;
}
.octagon:before {
    position: absolute;
    top: -3px; right: -3px; bottom: -3px; left: -3px;
    transform: rotate(45deg);
    content: '';
    border: inherit;
}    
.centered-text {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%) rotate(-45deg);
  text-align: center;
  font-size: 40px;
  font-weight: bold;
  color: #000000;
}
.centered-block {
    display: block;
}
</style>
</head>
<body>
    <div class="centered-block">
        <div class="octagonWrap">
            <div class='octagon'>
				<div class="centered-text">]] .. msg .. [[
				</div>
			</div>
        </div>
    </div>
</body>
</html>
]]
	
	logger.debugLog('oidcclient.errorResponseHTML: ' .. msg)
	HTTPResponse.setStatusCode(statusCode or 400)
	HTTPResponse.setStatusMsg("Bad Request")
	HTTPResponse.setBody(htmlContent)
	
	Control.responseGenerated(true)
end

--[[
    errorResponseJSON
    Use for returning a JSON error to the client

--]]
local function errorResponseJSON(msg, statusCode)

    local errJSON = {
        ["error"] = "invalid_request",
        ["error_description"] = msg
    }

    logger.debugLog('oidcclient.errorResponseJSON: ' .. cjson.encode(errJSON))
    HTTPResponse.setStatusCode(statusCode or 400)
    HTTPResponse.setStatusMsg("Bad Request")
    HTTPResponse.setHeader("content-type", "application/json")
    HTTPResponse.setHeader("cache-control", "no-store")
    HTTPResponse.setBody(cjson.encode(errJSON))
    Control.responseGenerated(true)
end

--[[
    errorResponseSLO
    Used for the single logout flow. Returns a HTML error
    for GET requests, and JSON otherwise.

--]]
local function errorResponseSLO(msg, statusCode)
    if (HTTPRequest.getMethod() == "GET") then
        errorResponseHTML(msg, statusCode)
    else
        errorResponseJSON(msg, statusCode)
    end
end

local function sendRedirect(url)
    --logger.debugLog('oidcclient.sendRedirect: ' .. logger.dumpAsString(url))
	HTTPResponse.setStatusCode(302)
	HTTPResponse.setStatusMsg("Found")
	HTTPResponse.setHeader("location", url)
	Control.responseGenerated(true)

end

--[[
    opDiscovery
    Used to retrieve and cache the well-known endpoint of the OP
--]]
local function performOPDiscovery(issuerConfig)
    local discoveryURL = issuerConfig["op_issuer_uri"] .. "/.well-known/openid-configuration"

    return cachedURLRetriever.getURL(
        discoveryURL,
        {
            ["skipTLSVerify"] = (issuerConfig["skipTLSVerify"] or false),
            ["headers"] ={
                ["accept"] = "application/json"
            },
            ["returnAsJSON"] = true,
            ["ignoreCache"] = false
        }
    )
end

--[[
    buildClientAssertionJWT
    Common function for building client assertion jwt
--]]
local function buildClientAssertionJWT(issuerConfig, options)
    local header = {
        ["alg"] = options.alg
    }
    if (options["kid"]) then
        header["kid"] = options["kid"]
    end

    local claims = {
        ["iss"] = issuerConfig["client_id"],
        ["sub"] = issuerConfig["client_id"],
        ["aud"] = options["aud"],
        ["exp"] = math.floor(os.time() + 120),
        ["jti"] = baseutils.to_url64(cryptoLite.randomBytes(32))
    }

    local jwtGenerateOptions = {
        header = header,
        claims = claims,
        algorithm = options.alg,
        key = options.key
    }
    return jwtUtils.generate(jwtGenerateOptions)
end

--[[
    buildClientAssertionClientSecretJWT
    Used to build a JWT for client authentication using the client_secret_jwt authentication method
--]]
local function buildClientAssertionClientSecretJWT(issuerConfig, options)
    options.alg = "HS256"
    options.key = issuerConfig["client_secret"]

    return buildClientAssertionJWT(issuerConfig, options)
end


--[[
    buildClientAssertionPrivateKeyJWT
    Used to build a JWT for client authentication using the private_key_jwt authentication method
--]]
local function buildClientAssertionPrivateKeyJWT(issuerConfig, options)
    options.alg = issuerConfig["jwkPrivateKey"]["alg"]
    options.kid = cryptoLite.generateJWKThumbprint(issuerConfig["jwkPublicKey"])
    options.key = cryptoLite.jwkToPEM(issuerConfig["jwkPrivateKey"])

    return buildClientAssertionJWT(issuerConfig, options)
end

local function updateIssuerConfig(issuerConfig, opMetadata)
    --
    -- determine which client authentication method we will use
    -- if the client configuration contains a "preferred_client_auth_method" then we use that, otherwise
    -- this is determined in a prioritized fashion from most to least perferred being
    --    "private_key_jwt"
    --    "client_secret_jwt"
    --    "client_secret_post"
    --    "client_secret_basic"
    --
    -- In order to use a particular prioritized method, the OP has to support it, 
    -- and the client configuration needs to have the necessary config parameters.
    --
    local client_auth_method = nil
    if issuerConfig["preferred_client_auth_method"] then
        client_auth_method = issuerConfig["preferred_client_auth_method"]
    else
        if opMetadata["token_endpoint_auth_methods_supported"] then
            -- use private_key_jwt if op and client support it
            if (hasValue(opMetadata["token_endpoint_auth_methods_supported"], "private_key_jwt") and issuerConfig["privateKey"]) then
                client_auth_method = "private_key_jwt"
            elseif (issuerConfig["client_secret"]) then
                -- there is obviously no point in checking any of these in the opMetadata if the client does not have a secret
                if (hasValue(opMetadata["token_endpoint_auth_methods_supported"], "client_secret_jwt")) then
                    client_auth_method = "client_secret_jwt"
                elseif (hasValue(opMetadata["token_endpoint_auth_methods_supported"], "client_secret_post")) then
                    client_auth_method = "client_secret_post"
                elseif (hasValue(opMetadata["token_endpoint_auth_methods_supported"], "client_secret_basic")) then
                    client_auth_method = "client_secret_basic"
                end
            end
        else
            -- per https://openid.net/specs/openid-connect-discovery-1_0.html the default is client_secret_basic
            -- we will use this so long as there is a client_secret in the config
            if issuerConfig["client_secret"] then
                client_auth_method = "client_secret_basic"
            end
        end
    end

    -- could still be nil for public clients or if there is a problem with the opMetadata
    if client_auth_method then
        issuerConfig["client_auth_method"] = client_auth_method
    end

    -- check that the opMetadata includes a response_types_supported, and that this includes the
    -- response type configured for the client. If there is no response type configured for the client
    -- we will default it to "code"
    if (not issuerConfig["response_type"]) then
        issuerConfig["response_type"] = "code"
    end
    if (not opMetadata["response_types_supported"] or not hasValue(opMetadata["response_types_supported"], issuerConfig["response_type"])) then
        logger.debugLog("updateIssuerConfig: ERROR - the opMetadata did not contain a matching client response_type: " 
            .. logger.dumpAsString(issuerConfig["response_type"]) .. 
            " in response_types_supported: " .. logger.dumpAsString(opMetadata["response_types_supported"]))
    end

    --
    -- Validate or default the scopes
    --
    if (not issuerConfig["scope"]) then
        issuerConfig["scope"] = {"openid"}
    end
    -- sanity check with warning output against 
    if (opMetadata["scopes_supported"]) then
        for _, s in ipairs(issuerConfig["scope"]) do
            if (not hasValue(opMetadata["scopes_supported"], s)) then
                logger.debugLog("updateIssuerConfig: WARNING - client configuration contains scope not supported by server: " .. s)
            end
        end
    end

    -- determine if we are going to use PKCE
    local code_challenge_method = nil
    if (opMetadata["code_challenge_methods_supported"]) then
        if (hasValue(opMetadata["code_challenge_methods_supported"], "S256")) then
            code_challenge_method = "S256"
        elseif (hasValue(opMetadata["code_challenge_methods_supported"], "plain")) then
            code_challenge_method = "plain"
        end
    end
    if code_challenge_method then
        issuerConfig["code_challenge_method"] = code_challenge_method
    end

    -- determine if we are going to do pushed authorization requests (PAR)
    local performPAR = false
    if (issuerConfig["prefer_pushed_authorization_requests"] and opMetadata["pushed_authorization_request_endpoint"]) then
        performPAR = true
    end
    issuerConfig["performPAR"] = performPAR
end


--[[
    parRequest
    Perform a pushed authorization request and return the request_uri or nil if there is a problem
--]]
local function parRequest(issuerConfig, opMetadata, paramMap)
    local result = nil

    -- really import - make sure we do not use the shared cookie store for these requests
    -- see: https://daurnimator.github.io/lua-http/0.3/#http.request.cookie_store
    -- NOTE WELL: defaults to a shared store.
    local newCookieStore = httpcookie.new_store()

    local req = httpreq.new_from_uri(opMetadata["pushed_authorization_request_endpoint"])
    req.cookie_store = newCookieStore

    -- update request HTTP headers
    -- note use of upsert here (rather than append) to replace any defaults
    req.headers:upsert("content-type", "application/x-www-form-urlencoded")
    req.headers:upsert("accept", "application/json")
    req.headers:upsert(":method", "POST")

    -- set up client authentication based on issuerConfig["client_auth_method"]
    if (issuerConfig["client_auth_method"] == "client_secret_basic") then
        req.headers:upsert("authorization", "Basic " .. baseutils.to_base64(issuerConfig["client_id"] .. ':' .. issuerConfig["client_secret"]))
    elseif (issuerConfig["client_auth_method"] == "client_secret_post") then
        paramMap["client_id"] = issuerConfig["client_id"]
        paramMap["client_secret"] = issuerConfig["client_secret"]
    elseif (issuerConfig["client_auth_method"] == "client_secret_jwt" or issuerConfig["client_auth_method"] == "private_key_jwt") then
        paramMap["client_id"] = issuerConfig["client_id"]
        paramMap["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        local clientAssertionOptions = {
            ["aud"] = opMetadata["pushed_authorization_request_endpoint"]
        }
        if (issuerConfig["client_auth_method"] == "client_secret_jwt") then
            paramMap["client_assertion"] = buildClientAssertionClientSecretJWT(issuerConfig, clientAssertionOptions)
        else
            paramMap["client_assertion"] = buildClientAssertionPrivateKeyJWT(issuerConfig, clientAssertionOptions)
        end
    end
    -- TODO add other authentication methods

    -- set post body params
    local body = formsModule.getPostBody(paramMap)
    req:set_body(body)

    -- we are going to use TLS	
    req.ctx = tls.new_client_context()

    -- ignore SSL cert errors - risky, don't do it unless you have to
    if (issuerConfig["skipTLSVerify"]) then 
        req.ctx:setVerify(require "openssl.ssl.context".VERIFY_NONE)
    end

    local headers, stream = assert(req:go())

    local httpStatusCode = headers:get ":status"
    --logger.debugLog("parRequest HTTP response status: " .. httpStatusCode)
    if httpStatusCode == "201" then
        local rspbody = assert(stream:get_body_as_string())
        if not (rspbody == nil or (not rspbody)) then
                -- example: {"request_uri":"urn:ietf:params:oauth:request_uri:09NMA6BTuC463c-7r0f82rF9puJTfoNl6DqJVitKf8g","expires_in":600}
                local parResponse = cjson.decode(rspbody)
                result = parResponse["request_uri"]
        else
            logger.debugLog("parRequest: no body in HTTP response")
        end
    else
        -- attempt to get rspbody so we can see the error
        local rspbody = stream:get_body_as_string()
        logger.debugLog("parRequest: invalid HTTP response code: " .. httpStatusCode .. " rspbody: " .. logger.dumpAsString(rspbody))
    end

    return result
end

local function jwksContainsKID(jwksData, kid)
    if (jwksData and jwksData["keys"]) then
        for _, k in ipairs(jwksData["keys"]) do
            if k["kid"] == kid then
                return true
            end
        end
    end
    return false
end

local function validateIDToken(issuerConfig, opMetadata, tokenResponse)
    local validationResult = {
        ["valid"] = false,
        ["error"] = "Unknown error"
    }

    local id_token = tokenResponse["id_token"]

    -- first decode the id_token and make sure it is structually sound 
    -- we also want to get the signing kid from the header this way
    local success, decodeResult = pcall(jwtUtils.decode, id_token)
    if (not success) then
        logger.debugLog("validateIDToken: could not decode id_token: " .. logger.dumpAsString(decodeResult))
        validationResult["error"] = decodeResult
        return validationResult
    end

    -- Get the JWKS endpoint from the OP metadata and retrieve it.
    -- We then first check it in a cached manner to see if it contains a kid matching
    -- that of the id_token. If it does, great, we will use that for signature validation
    -- If it doesn't, then we will try once to re-retrieve the JWKS endpoint in case the
    -- kid is new since we last cached it. If it still isn't there, then we give up.
    local jwksEndpoint = opMetadata["jwks_uri"]
    local jwksData = cachedURLRetriever.getURL(
        jwksEndpoint,
        {
            ["skipTLSVerify"] = issuerConfig["skipTLSVerify"] or false,
            ["headers"] ={
                ["accept"] = "application/json"
            },
            ["returnAsJSON"] = true,
            ["ignoreCache"] = false
        }
    )
    if (not jwksData) then
        local errStr = "validateIDToken: unable to retrieve JWKS from: " .. logger.dumpAsString(jwksEndpoint)
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    if not jwksContainsKID(jwksData, decodeResult["jwtHeader"]["kid"]) then
        -- try once more without cache
        jwksData = cachedURLRetriever.getURL(
                jwksEndpoint,
                {
                    ["skipTLSVerify"] = (issuerConfig["skipTLSVerify"] or false),
                    ["headers"] ={
                        ["accept"] = "application/json"
                    },
                    ["returnAsJSON"] = true,
                    ["ignoreCache"] = true
                }
            )
    end

    if not jwksContainsKID(jwksData, decodeResult["jwtHeader"]["kid"]) then
        local errStr = "validateIDToken: could not find jwt kid: " .. logger.dumpAsString(decodeResult["jwtHeader"]["kid"]) .. " in JWKS from: " .. logger.dumpAsString(jwksEndpoint)
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    -- make sure the algorithm is acceptable to us
    local allowedAlgs = { "RS256", "ES256", "HS256" }
    if (not hasValue(allowedAlgs, decodeResult["jwtHeader"]["alg"])) then
        local errStr = "validateIDToken: id_token has unacceptable alg: " .. logger.dumpAsString(decodeResult["jwtHeader"]["alg"])
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    -- make sure the typ is JWT
    --if (not (decodeResult["jwtHeader"]["typ"] == "JWT")) then
    --    local errStr = "validateIDToken: id_token has unacceptable typ: " .. logger.dumpAsString(decodeResult["jwtHeader"]["typ"])
    --    logger.debugLog(errStr)
    --    validationResult["error"] = errStr
    --    return validationResult
    --end

    -- try the signature validation now
    local success, jwtValidationResult = pcall(
        jwtUtils.validate,
        {
            jwt = id_token,
            algorithm = decodeResult["jwtHeader"]["alg"],
            jwks = jwksData,
            validateExp = true,
            clockSkew = 60
        }
    )

    if (not success) then
        logger.debugLog("validateIDToken: could not validate id_token: " .. logger.dumpAsString(jwtValidationResult))
        validationResult["error"] = jwtValidationResult
        return validationResult
    end

    --
    -- perform other validation of the id_token claims
    --
    local idTokenClaims = jwtValidationResult["jwtClaims"]

    -- is the iss claim present and correct
    if (not (idTokenClaims["iss"] ~= nil and idTokenClaims["iss"] == issuerConfig["op_issuer_uri"])) then
        local errStr = "validateIDToken: invalid iss in id_token: " .. logger.dumpAsString(idTokenClaims["iss"])
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    -- is the aud present and either is our client_id, or contains at least one value which matches our client_id
    if (not(
        idTokenClaims["aud"] ~= nil and
        (
            (type(idTokenClaims["aud"]) == "string" and idTokenClaims["aud"] == issuerConfig["client_id"]) or 
            (type(idTokenClaims["aud"]) == "table" and hasValue(idTokenClaims["aud"], issuerConfig["client_id"]))
        )
    )) then
        local errStr = "validateIDToken: invalid aud in id_token: " .. logger.dumpAsString(idTokenClaims["aud"])
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    -- is the exp present and in the future (allowing for SKEW)?
    local now = os.time()
    local SKEW = 30
    if (not(idTokenClaims["exp"] ~= nil and (now-SKEW) < idTokenClaims["exp"])) then
        local errStr = "validateIDToken: invalid exp in id_token: " .. logger.dumpAsString(idTokenClaims["exp"]) .. " now: " .. tostring(now)
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    -- is the iat present and in the past (allowing for SKEW)?
    if (not(idTokenClaims["iat"] ~= nil and idTokenClaims["iat"] < (now+SKEW))) then
        local errStr = "validateIDToken: invalid iat in id_token: " .. logger.dumpAsString(idTokenClaims["iat"]) .. " now: " .. tostring(now)
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    -- is the nonce present and correct?
    if (not(idTokenClaims["nonce"] ~= nil and idTokenClaims["nonce"] == issuerConfig["nonce"])) then
        local errStr = "validateIDToken: invalid nonce in id_token: " .. logger.dumpAsString(idTokenClaims["nonce"]) .. " nonce: " .. logger.dumpAsString(issuerConfig["nonce"])
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    -- if the s_hash is present, validate it
    if (idTokenClaims["s_hash"] ~= nil) then
        local sHash = computeLeftMostHash(issuerConfig["state"])
        if not(sHash == idTokenClaims["s_hash"]) then
            local errStr = "validateIDToken: invalid s_hash in id_token: " .. logger.dumpAsString(idTokenClaims["s_hash"]) .. " state: " .. logger.dumpAsString(issuerConfig["state"])
            logger.debugLog(errStr)
            validationResult["error"] = errStr
            return validationResult
        end
    end

    -- if the at_hash is present, validate it
    if (idTokenClaims["at_hash"] ~= nil) then
        local atHash = computeLeftMostHash(tokenResponse["access_token"])
        if not(atHash == idTokenClaims["at_hash"]) then
            local errStr = "validateIDToken: invalid at_hash in id_token: " .. logger.dumpAsString(idTokenClaims["at_hash"]) .. " access_token: " .. logger.dumpAsString(tokenResponse["access_token"])
            logger.debugLog(errStr)
            validationResult["error"] = errStr
            return validationResult
        end
    end

    -- if the rt_hash is present, validate it
    if (idTokenClaims["rt_hash"] ~= nil) then
        local rtHash = computeLeftMostHash(tokenResponse["refresh_token"])
        if not(rtHash == idTokenClaims["rt_hash"]) then
            local errStr = "validateIDToken: invalid rt_hash in id_token: " .. logger.dumpAsString(idTokenClaims["rt_hash"]) .. " refresh_token: " .. logger.dumpAsString(tokenResponse["refresh_token"])
            logger.debugLog(errStr)
            validationResult["error"] = errStr
            return validationResult
        end
    end

    --
    -- There are other claims in the id_token that we might choose to conditionally validate in the future including
    --
    -- jti (would be best if we have a global nonce cache before validating that)
    -- auth_time (meaningful if we add support for max_age in authorization requests)
    -- azp (meaningful if the aud claim contains more than 1 value)
    -- amr (authentication method reference - see RFC8176)
    -- acr (authentication context reference - depends on specific OIDC profiles like OpenBanking)
    -- sid (session identifier, may be later used in SLO)
    --

    validationResult["valid"] = true
    validationResult["jwtHeader"] = jwtValidationResult["jwtHeader"]
    validationResult["jwtClaims"] = jwtValidationResult["jwtClaims"]

    return validationResult
end

--[[
    processKickoffURL
    Used to kickoff a new OIDC login flow
--]]
local function processKickoffURL()

    local qsParams = formsModule.getQueryParams(HTTPRequest.getURL())
    local issuer = qsParams["issuer"] or oidcClientConfig["default_issuer"]
    local issuerConfig = nil
    if (oidcClientConfig["issuers"][issuer]) then
        -- this encode/decode is to ensure we get a new copy and don't a singleton config value
        issuerConfig = cjson.decode(cjson.encode(oidcClientConfig["issuers"][issuer]))
    end

    if (not issuerConfig) then
        errorResponseHTML("Unable to determine issuer config")
        return
    end

    -- remember the issuer as part of this object
    issuerConfig["issuer"] = issuer

    -- get the OP metadata
    local opMetadata = performOPDiscovery(issuerConfig)
    if (not opMetadata) then
        errorResponseHTML("Unable to retrieve OP metadata")
        return
    end
    --logger.debugLog("processKickoffURL: opMetadata: " .. cjson.encode(opMetadata))

    --
    -- update the issuerConfig based on the opMetadata
    -- this determines things like:
    --   which client authentication method will be used
    --   validate or default the scope
    --   determine if we are going to use PKCE
    --
    updateIssuerConfig(issuerConfig, opMetadata)

    -- figure out our redirect URL
    local redirectURI = getBaseURL() .. '/oidcredirect/' .. issuer

    -- create random state and nonce values and remember them
    local state = baseutils.to_url64(cryptoLite.randomBytes(32))
    local nonce = baseutils.to_url64(cryptoLite.randomBytes(32))
    issuerConfig["state"] = state
    issuerConfig["nonce"] = nonce

    --
    -- build an authorize URL and its parameters
    --
    local authorizeURL = opMetadata["authorization_endpoint"]
    local paramMap = {
        ["client_id"] = issuerConfig["client_id"],
        ["response_type"] = issuerConfig["response_type"],
        ["scope"] = table.concat(issuerConfig["scope"], " "),
        ["state"] = state,
        ["nonce"] = nonce,
        ["redirect_uri"] = redirectURI
    }

    -- optional parameters
    -- TODO - support things like reponse_mode

    -- if we are using PKCE, set that up now
    if (issuerConfig["code_challenge_method"]) then
        local code_verifier = generateRandomString(64)
        issuerConfig["code_verifier"] = code_verifier

        -- default to plain, override for S256
        local code_challenge = code_verifier
        if (issuerConfig["code_challenge_method"] == "S256") then
            code_challenge = cryptoLite.sha256(code_verifier)
        end

        paramMap["code_challenge_method"] = issuerConfig["code_challenge_method"]
        paramMap["code_challenge"] = code_challenge
    end

    -- if we are doing pushed authorization requests, do that now
    if (issuerConfig["performPAR"]) then
        local requestURI = parRequest(issuerConfig, opMetadata, paramMap)

        if (not requestURI) then
            errorResponseHTML("Unable to perform PAR request")
            return
        end

        local newAznParams = {
            ["client_id"] = issuerConfig["client_id"],
            ["request_uri"] = requestURI
        }

        authorizeURL = authorizeURL .. "?"
        authorizeURL = authorizeURL .. formsModule.getPostBody(newAznParams)
    else
        -- regular (non-PAR) request parameters
        authorizeURL = authorizeURL .. "?"
        authorizeURL = authorizeURL .. formsModule.getPostBody(paramMap)
    end

    -- store state information for use on redirect uri processing
    local stateKey = "oidc_" .. issuer
    Session.setSessionAttribute(stateKey, cjson.encode(issuerConfig))

    --logger.debugLog("processKickoffURL: redirecting to: " .. authorizeURL)

    HTTPResponse.setStatusCode(302)
    HTTPResponse.setStatusMsg("Found")
    HTTPResponse.setHeader("Location", authorizeURL)
    HTTPResponse.setBody('Redirecting...')
    
    Control.responseGenerated(true)
end

--[[
    setupRedisSLOKeys
    Establishes a lookup key based on the provided sid which will refer to the
    user entry key, and the tagvalue_session_index 
--]]
local function setupRedisSLOKeys(sid, username, session_index)
    --logger.debugLog("oidcclient.setupRedisSLOKeys called with username: " .. logger.dumpAsString(username) .. " sid: " .. logger.dumpAsString(sid) .. " session_index: " .. logger.dumpAsString(session_index))
    local val = {
        ["username"] = string.lower(username),
        ["session_index"] = session_index
    }
    -- redis must be configured
    if redisClient == nil then
        redisClient = redisHelper.getRedisClient()
    end

    local key = "OIDC_SID_" .. string.lower(sid)
    redisHelper.setGlobalKey(redisClient, key, cjson.encode(val), MAX_SESSION_LIFETIME)
end

--[[
    sloUsingRedis

    Deletes either all sessionf for username (if no sid is provided)
    or just tries to find and delete the session represented by sid (if sid is provided)
--]]
local function sloUsingRedis(username, sid)

    local result = false
    --logger.debugLog("oidcclient.sloUsingRedis called with username: " .. logger.dumpAsString(username) .. " sid: " .. logger.dumpAsString(sid))

    -- redis must be configured
    if redisClient == nil then
        redisClient = redisHelper.getRedisClient()
    end

    if (sid ~= nil) then
        local key = "OIDC_SID_" .. string.lower(sid)
        local sidData = redisHelper.getGlobalKey(redisClient, key)
        --logger.debugLog("oidcclient.sloUsingRedis attempting session logout. Lookup of key: " .. logger.dumpAsString(key) .. " sidData: " .. logger.dumpAsString(sidData))
        if (sidData ~= nil) then
            local sidDataJSON = cjson.decode(sidData)
            local redisSessionID = redisHelper.findSessionForUserWithMatchingTagValueSessionIndex(redisClient, sidDataJSON["username"], sidDataJSON["session_index"])
            if redisSessionID then
                logger.debugLog("oidcclient.sloUsingRedis deleting redis session ID: " .. logger.dumpAsString(redisSessionID))
                redisHelper.deleteSessionByID(redisClient, redisSessionID)
                result = true
            else
                logger.debugLog("oidcclient.sloUsingRedis unable to locate redis sesson for username: " .. logger.dumpAsString(username) .. " sid: " .. logger.dumpAsString(sid))
                result = false
            end

            -- cleanup the sid key as well since we have processed it
            redisHelper.deleteGlobalKey(redisClient, key)
        else
            logger.debugLog("oidcclient.sloUsingRedis no session found for sid: " .. logger.dumpAsString(sid))
            result = false
        end
    else
        -- sub must be present, so delete all those sessions
        logger.debugLog("oidcclient.sloUsingRedis deleting all sessions for user: " .. logger.dumpAsString(username))
        redisHelper.deleteSessionsForUser(redisClient, string.lower(username))
        result = true
    end

    return result
end


--[[
    performLogin
    Implement this however you like to complete login.

    The default implementation sets:
      - the username as the sub assuming this is an external user (typical for IAG)
      - the AUTHENTICATION_LEVEL to 1
      - sets attributes for all of the id_token claims
      - adds the access_token and refresh_token from the tokenResponse if provided
      - adds the DPoP private key if we have one
--]]
local function performLogin(options)
    local issuer = options.issuer
    local tokenResponse = options.tokenResponse
    local idTokenHeader = options.idTokenHeader
    local idTokenClaims = options.idTokenClaims
    local idToken = options.idToken
    local dpopKeyPair = options.dpopKeyPair

    --logger.debugLog("performLogin: logging in as: " .. idTokenClaims["sub"])
    Authentication.setUserIdentity(idTokenClaims["sub"], true)
    Authentication.setAuthLevel(1)

    if (tokenResponse["access_token"]) then
        Authentication.setAttribute("access_token", tokenResponse["access_token"])
    end
    if (tokenResponse["token_type"]) then
        Authentication.setAttribute("token_type", tokenResponse["token_type"])
    end
    if (tokenResponse["refresh_token"]) then
        Authentication.setAttribute("refresh_token", tokenResponse["refresh_token"])
    end

    -- add all id_token claims, treating tables as JSON and either stringifying them
    -- or if they are an array, treating as a multi-valued attribute
    for k,v in pairs(idTokenClaims) do
        if type(v) == 'table' then
            if (isArray(v)) then
                -- treat as multi-valued string attribute
                local strArray = {}
                for _, v2 in ipairs(v) do
                    if type(v2) == 'table' then
                        table.insert(strArray, cjson.encode(v2))
                    else
                        table.insert(strArray, logger.dumpAsString(v2))
                    end
                end
                Authentication.setAttribute(k, strArray)
            else
                -- treat as JSON and encode as string
                Authentication.setAttribute(k, cjson.encode(v))
            end
        else
            -- stringify the value
            Authentication.setAttribute(k, logger.dumpAsString(v))
        end
    end

    -- If there is a sid claim in the id token, and Redis is configured then setup SLO support
    if idTokenClaims["sid"] and redisHelper.isRedisConfigured() then
        setupRedisSLOKeys(idTokenClaims["sid"], string.lower(idTokenClaims["sub"]), Session.getCredentialAttribute("tagvalue_session_index"))

        -- we also put the issuer and id_token into session attributes for SLO so that it can be used as the id_token_hint paramater in a redirect to
        -- the OP's SLO endpoint for the given issuer
        Session.setSessionAttribute("issuer", issuer)
        Session.setSessionAttribute("id_token", idToken)
    end

    -- This is put in the session as its not needed in the credential. In fact we only keep the 
    -- key information in the session so that the SAMPLE transformation for sampleresourcerequest will 
    -- be able to work. So if you are not using that, you can remove this section completely.
    if (dpopKeyPair) then
        Session.setSessionAttribute("dpop_private_key", cjson.encode(dpopKeyPair["jwkPrivateKey"]))
        Session.setSessionAttribute("dpop_public_key", cjson.encode(dpopKeyPair["jwkPublicKey"]))
        Session.setSessionAttribute("dpop_alg", dpopKeyPair["alg"])
    end
end

local function createDPoPKeyPair(alg)
    local keypair = nil
    if (alg == "RS256") then
        local rsaPublicKey, rsaPrivateKey = cryptoLite.generateRSAKeyPair(2048)
        rsaPublicKeyJWK = cryptoLite.PEMtoJWK(rsaPublicKey)
        rsaPublicKeyJWK["alg"] = "RS256"
        rsaPrivateKeyJWK = cryptoLite.PEMtoJWK(rsaPrivateKey)
        rsaPrivateKeyJWK["alg"] = "RS256"
        keypair = {
            alg = "RS256",
            publicKey = rsaPublicKey,
            privateKey = rsaPrivateKey,
            jwkPublicKey = rsaPublicKeyJWK,
            jwkPrivateKey = rsaPrivateKeyJWK
        }
    elseif (alg == "ES256") then
        local ecPublicKey, ecPrivateKey = cryptoLite.generateECDSAKeyPair()
        ecPublicKeyJWK = cryptoLite.PEMtoJWK(ecPublicKey)
        ecPublicKeyJWK["alg"] = "ES256"
        ecPrivateKeyJWK = cryptoLite.PEMtoJWK(ecPrivateKey)
        ecPrivateKeyJWK["alg"] = "ES256"
        keypair = {
            alg = "ES256",
            publicKey = ecPublicKey,
            privateKey = ecPrivateKey,
            jwkPublicKey = ecPublicKeyJWK,
            jwkPrivateKey = ecPrivateKeyJWK
        }
    else
        logger.debugLog("Unsupported DPoP algorithm: " .. alg)
    end
    --logger.debugLog("createDPoPKeyPair returning: " .. cjson.encode(keypair))
    return keypair
end

local function createDPoPProof(options)
    local keypair = options.keypair
    local htm = options.htm
    local htu = options.htu
    local iat = os.time()
    local jti = baseutils.to_url64(cryptoLite.randomBytes(32))
    local claims = {
        htm = htm,
        htu = htu,
        iat = iat,
        jti = jti
    }

    -- if an access_token is included in the options, create ath
    if (options.access_token) then
        claims["ath"] = cryptoLite.sha256(options.access_token)
    end

    local header = {
        typ = "dpop+jwt",
        alg = keypair.alg,
        jwk = keypair.jwkPublicKey
    }
    local dpopProof = jwtUtils.generate({
        header = header,
        claims = claims,
        algorithm = keypair.alg,
        key = keypair.privateKey
    })
    return dpopProof
end

--[[
    processRedirectURL
    Used to process a redirect url request in the OIDC login flow
--]]
local function processRedirectURL()
    _,_,issuer = string.find(HTTPRequest.getURL(), "/oidcredirect/(.+)%?")
    if (not issuer or not(oidcClientConfig["issuers"][issuer])) then
        errorResponseHTML("Unable to determine issuer config")
        return
    end

    -- unpack response parameters
    local responseParams = nil
    if (HTTPRequest.getMethod() == "POST") then
        responseParams = formsModule.getPostParams(HTTPRequest.getBody())
    elseif (HTTPRequest.getMethod() == "GET") then
        responseParams = formsModule.getQueryParams(HTTPRequest.getURL())
    else
        errorResponseHTML("Invalid HTTP method")
        return
    end

    if not responseParams then
        errorResponseHTML("Invalid request")
        return
    end

    -- make sure we have session state for this response and the remembered state equals the provided state
    local stateKey = "oidc_" .. issuer
    local issuerConfig = nil
    local issuerConfigStr = Session.getSessionAttribute(stateKey)
    if (issuerConfigStr) then
        issuerConfig = cjson.decode(issuerConfigStr)
    end
    if (not issuerConfig or not (responseParams["state"] == issuerConfig["state"])) then
        errorResponseHTML("Invalid state")
        return
    end

    -- retrieve the opMetadata, this should be cached anyway
    local opMetadata = performOPDiscovery(issuerConfig)
    if (not opMetadata) then
        errorResponseHTML("Unable to retrieve OP metadata")
        return
    end

    -- figure out our redirect URL
    local redirectURI = getBaseURL() .. '/oidcredirect/' .. issuer

    -- build the request to the token endpoint
    local paramMap = {
        ["grant_type"] = "authorization_code",
        ["client_id"] = issuerConfig["client_id"],
        ["redirect_uri"] = redirectURI,
        ["code"] = responseParams["code"]
    }

    -- setup client authentication paramaters
    if (issuerConfig["client_auth_method"] == "client_secret_post") then
        paramMap["client_secret"] = issuerConfig["client_secret"]
    elseif (issuerConfig["client_auth_method"] == "client_secret_jwt" or issuerConfig["client_auth_method"] == "private_key_jwt") then
        paramMap["client_id"] = issuerConfig["client_id"]
        paramMap["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        local clientAssertionOptions = {
            ["aud"] = opMetadata["token_endpoint"]
        }
        if (issuerConfig["client_auth_method"] == "client_secret_jwt") then
            paramMap["client_assertion"] = buildClientAssertionClientSecretJWT(issuerConfig, clientAssertionOptions)
        else
            paramMap["client_assertion"] = buildClientAssertionPrivateKeyJWT(issuerConfig, clientAssertionOptions)
        end
    end
    -- TODO add support for other authentication methods

    -- if we are using PKCE, include the code_verifier
    if (issuerConfig["code_challenge_method"]) then
        paramMap["code_verifier"] = issuerConfig["code_verifier"]
    end

    -- if we are using DPoP, create the DPoP keypair and DPoP proof now
    local dpopKeyPair = nil
    local dpopProof = nil
    if (issuerConfig["dpop_signing_alg"]) then
        -- currently we only support these signing algs for DPoP
        local allowedDPoPAlgs = { "RS256", "ES256" }
        if not hasValue(allowedDPoPAlgs, issuerConfig["dpop_signing_alg"]) then
            errorResponseHTML("Client is configured with invalid DPoP signing algorithm: " .. issuerConfig["dpop_signing_alg"])
            return
        end

        dpopKeyPair = createDPoPKeyPair(issuerConfig["dpop_signing_alg"])
        dpopProof = createDPoPProof({
            keypair = dpopKeyPair,
            htm = "POST",
            htu = opMetadata["token_endpoint"]
        })
        --logger.debugLog("dpopProof: " .. logger.dumpAsString(dpopProof))
    end

    -- call the token endpoint
    local tokenEndpoint = opMetadata["token_endpoint"]

	local req = httpreq.new_from_uri(tokenEndpoint)
	
	-- update request HTTP headers
	-- This includes setting the BA header if necessary, content-type, accept, and the HTTP method
	-- note use of upsert here (rather than append) to replace any defaults
    if (issuerConfig["client_auth_method"] == "client_secret_basic") then
	    req.headers:upsert("authorization", "Basic " .. baseutils.to_base64(issuerConfig["client_id"] .. ':' .. issuerConfig["client_secret"]))
    end
    -- if we are using DPoP, include the DPoP proof header
    if (dpopProof) then
        req.headers:append("dpop", dpopProof)
	end
	req.headers:upsert("content-type", "application/x-www-form-urlencoded")
	req.headers:upsert("accept", "application/json")
	req.headers:upsert(":method", "POST")


	-- we are going to use TLS	
	req.ctx = tls.new_client_context()
	
    -- ignore SSL cert errors - risky, don't do it unless you have to
    if (true or issuerConfig["skipTLSVerify"]) then
        req.ctx:setVerify(require "openssl.ssl.context".VERIFY_NONE)
    end
	
    local body = formsModule.getPostBody(paramMap)
	req:set_body(body)
	--local headers, stream = assert(req:go())

    local headers = nil
    local stream = nil
    local success, goResults = pcall(
        function()
            local headers, stream = req:go()
            return {
                headers = headers,
                stream = stream
            }
        end
    )
    if not success then
        logger.debugLog("Unable to exchange code for token: " .. logger.dumpAsString(goResults))
         errorResponseHTML("Unable to exchange code for token: " .. logger.dumpAsString(goResults))
         return
    else
        headers = goResults.headers
        stream = goResults.stream
    end

	local httpStatusCode = headers:get ":status"
    local tokenResponse = nil
	--logger.debugLog("processRedirectURL HTTP response status: " .. httpStatusCode)
	if httpStatusCode == "200" then
		local rspbody = assert(stream:get_body_as_string())
		if not (rspbody == nil or (not rspbody)) then
			tokenResponse = cjson.decode(rspbody)
		else
			logger.debugLog("processRedirectURL: no body in HTTP response")
		end
	else
		logger.debugLog("processRedirectURL: invalid HTTP response code: " .. httpStatusCode)
	end

    if not tokenResponse then
        -- see if we can get a response body for futher info
        local rspbody = stream:get_body_as_string()
        errorResponseHTML("Unable to exchange code for token: " .. logger.dumpAsString(rspbody))
        return
    end

    --logger.debugLog("processRedirectURL: tokenResponse: " .. cjson.encode(tokenResponse))

    -- now we validate the id_token
    local idTokenValidationResults = validateIDToken(issuerConfig, opMetadata, tokenResponse)


    if not idTokenValidationResults["valid"] then
        errorResponseHTML("Invalid ID token: " .. idTokenValidationResults["error"])
        return
    end

    --
    -- Success! We will now remove the session state information, and login
    --
    Session.removeSessionAttribute(stateKey)
    local loginOptions = {
        issuer = issuer,
        tokenResponse = tokenResponse, 
        idTokenHeader = idTokenValidationResults["jwtHeader"], 
        idTokenClaims = idTokenValidationResults["jwtClaims"],
        idToken = tokenResponse["id_token"]
    }
    -- if we are using DPoP, include the DPoP keypair such that the private key can be added to the credential
    -- or Session attributes for potential later use
    if (dpopKeyPair) then
        loginOptions["dpopKeyPair"] = dpopKeyPair
    end

    performLogin(loginOptions)
end

--[[
    validateLogoutToken
    validate a logout token per https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation
--]]
local function validateLogoutToken(issuerConfig, opMetadata, logoutToken)
    local validationResult = {
        ["valid"] = false,
        ["error"] = "Unknown error"
    }

    --logger.debugLog("validateLogoutToken called with logoutToken: " .. logger.dumpAsString(logoutToken))

    -- first decode the id_token and make sure it is structually sound 
    -- we also want to get the signing kid from the header this way
    local success, decodeResult = pcall(jwtUtils.decode, logoutToken)
    if (not success) then
        logger.debugLog("validateLogoutToken: could not decode logout_token: " .. logger.dumpAsString(decodeResult))
        validationResult["error"] = decodeResult
        return validationResult
    end

    -- Get the JWKS endpoint from the OP metadata and retrieve it.
    -- We then first check it in a cached manner to see if it contains a kid matching
    -- that of the id_token. If it does, great, we will use that for signature validation
    -- If it doesn't, then we will try once to re-retrieve the JWKS endpoint in case the
    -- kid is new since we last cached it. If it still isn't there, then we give up.
    local jwksEndpoint = opMetadata["jwks_uri"]
    local jwksData = cachedURLRetriever.getURL(
        jwksEndpoint,
        {
            ["skipTLSVerify"] = issuerConfig["skipTLSVerify"] or false,
            ["headers"] ={
                ["accept"] = "application/json"
            },
            ["returnAsJSON"] = true,
            ["ignoreCache"] = false
        }
    )
    if (not jwksData) then
        local errStr = "validateLogoutToken: unable to retrieve JWKS from: " .. logger.dumpAsString(jwksEndpoint)
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    if not jwksContainsKID(jwksData, decodeResult["jwtHeader"]["kid"]) then
        -- try once more without cache, but we will probably timeout the logout at the OP
        jwksData = cachedURLRetriever.getURL(
                jwksEndpoint,
                {
                    ["skipTLSVerify"] = (issuerConfig["skipTLSVerify"] or false),
                    ["headers"] ={
                        ["accept"] = "application/json"
                    },
                    ["returnAsJSON"] = true,
                    ["ignoreCache"] = true
                }
            )
    end

    if not jwksContainsKID(jwksData, decodeResult["jwtHeader"]["kid"]) then
        local errStr = "validateLogoutToken: could not find jwt kid: " .. logger.dumpAsString(decodeResult["jwtHeader"]["kid"]) .. " in JWKS from: " .. logger.dumpAsString(jwksEndpoint)
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    -- make sure the algorithm is acceptable to us
    local allowedAlgs = { "RS256", "ES256", "HS256" }
    if (not hasValue(allowedAlgs, decodeResult["jwtHeader"]["alg"])) then
        local errStr = "validateLogoutToken: logout_token has unacceptable alg: " .. logger.dumpAsString(decodeResult["jwtHeader"]["alg"])
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    -- make sure the typ is logout+jwt
    if (not (decodeResult["jwtHeader"]["typ"] == "logout+jwt")) then
        local errStr = "validateLogoutToken: logout_token has unacceptable typ: " .. logger.dumpAsString(decodeResult["jwtHeader"]["typ"])
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    -- try the signature validation now
    local success, jwtValidationResult = pcall(
        jwtUtils.validate,
        {
            jwt = logoutToken,
            algorithm = decodeResult["jwtHeader"]["alg"],
            jwks = jwksData,
            validateExp = true,
            clockSkew = 60
        }
    )

    if (not success) then
        logger.debugLog("validateLogoutToken: could not validate logout_token: " .. logger.dumpAsString(jwtValidationResult))
        validationResult["error"] = jwtValidationResult
        return validationResult
    end

    --
    -- perform other validation of the logout_token claims
    --
    local logoutTokenClaims = jwtValidationResult["jwtClaims"]

    -- is the iss claim present and correct
    if (not (logoutTokenClaims["iss"] ~= nil and logoutTokenClaims["iss"] == issuerConfig["op_issuer_uri"])) then
        local errStr = "validateLogoutToken: invalid iss in logout_token: " .. logger.dumpAsString(logoutTokenClaims["iss"])
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    -- is the aud present and either is our client_id, or contains at least one value which matches our client_id
    if (not(
        logoutTokenClaims["aud"] ~= nil and
        (
            (type(logoutTokenClaims["aud"]) == "string" and logoutTokenClaims["aud"] == issuerConfig["client_id"]) or 
            (type(logoutTokenClaims["aud"]) == "table" and hasValue(logoutTokenClaims["aud"], issuerConfig["client_id"]))
        )
    )) then
        local errStr = "validateLogoutToken: invalid aud in logout_token: " .. logger.dumpAsString(idTokenClaims["aud"])
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    -- is the exp present and in the future (allowing for SKEW)?
    local now = os.time()
    local SKEW = 30
    if (not(logoutTokenClaims["exp"] ~= nil and (now-SKEW) < logoutTokenClaims["exp"])) then
        local errStr = "validateLogoutToken: invalid exp in logout_token: " .. logger.dumpAsString(logoutTokenClaims["exp"]) .. " now: " .. tostring(now)
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    -- is the iat present and in the past (allowing for SKEW)?
    if (not(logoutTokenClaims["iat"] ~= nil and logoutTokenClaims["iat"] < (now+SKEW))) then
        local errStr = "validateLogoutToken: invalid iat in logout_token: " .. logger.dumpAsString(logoutTokenClaims["iat"]) .. " now: " .. tostring(now)
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    -- is at least one of sid or sub present?
    if (logoutTokenClaims["sid"] == nil and logoutTokenClaims["sub"] == nil) then
        local errStr = "validateLogoutToken: missing sid or sub in logout_token"
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    -- verify the events claim
    if (logoutTokenClaims["events"] == nil or logoutTokenClaims["events"]["http://schemas.openid.net/event/backchannel-logout"] == nil) then
        local errStr = "validateLogoutToken: missing events entry in logout_token"
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    -- make sure nonce is NOT present
    if (logoutTokenClaims["nonce"] ~= nil) then
        local errStr = "validateLogoutToken: invalid claim in logout_token: nonce"
        logger.debugLog(errStr)
        validationResult["error"] = errStr
        return validationResult
    end

    --
    -- There are other claims in the logout_token that we might choose to conditionally validate in the future including
    --
    -- jti (would be best if we have a global nonce cache before validating that)
    --

    validationResult["valid"] = true
    validationResult["jwtHeader"] = jwtValidationResult["jwtHeader"]
    validationResult["jwtClaims"] = jwtValidationResult["jwtClaims"]

    return validationResult
end

--[[
    processSingleLogout
    Used to process an SLO request in the OIDC single logout flow
--]]
local function processSingleLogout()
    -- for GET requests we try get the issuer from session attribute as this is a kickoff
    -- for POST requests, we try get from the URL
    local issuer = nil
    
    if (HTTPRequest.getMethod() == "GET") then
        issuer = Session.getSessionAttribute("issuer")
    elseif (HTTPRequest.getMethod() == "POST") then
        local _,_,issuerStr = string.find(HTTPRequest.getURL(), "/oidcslo/(.+)")
        issuer = issuerStr
    end

    -- we better have issuer now
    if (not issuer or not(oidcClientConfig["issuers"][issuer])) then
        errorResponseSLO("Unable to determine issuer config")
        return
    end

    local issuerConfig = nil
    if (oidcClientConfig["issuers"][issuer]) then
        -- this encode/decode is to ensure we get a new copy and don't a singleton config value
        issuerConfig = cjson.decode(cjson.encode(oidcClientConfig["issuers"][issuer]))
    end

    if (not issuerConfig) then
        errorResponseSLO("Unable to determine issuer config")
        return
    end

    -- remember the issuer as part of this object
    issuerConfig["issuer"] = issuer

    -- get the OP metadata
    local opMetadata = performOPDiscovery(issuerConfig)
    if (not opMetadata) then
        errorResponseSLO("Unable to retrieve OP metadata")
        return
    end
    --logger.debugLog("processSingleLogout: opMetadata: " .. cjson.encode(opMetadata))

    -- if backchannel logout is not supported by the OP, exit now
    if (not(opMetadata["backchannel_logout_supported"] or opMetadata["backchannel_logout_session_supported"])) then
        errorResponseSLO("Backchannel logout is not supported by the OP")
        return
    end

    -- if we cannot find the end_session_endpoint that is an error too
    if (not opMetadata["end_session_endpoint"]) then
        errorResponseSLO("Logout endpoint not found in OP metadata")
        return
    end

    -- for GET this is an SLO kickoff so we redirect to the OP's SLO endpoint with the id_token_hint
    if (HTTPRequest.getMethod() == "GET") then
        -- kickoff SLO
        local idToken = Session.getSessionAttribute("id_token")
        if not idToken then
            errorResponseSLO("processSingleLogout: Unable to retrieve id_token from session")
            return
        end
        
        local redirectURL = opMetadata["end_session_endpoint"] .. "?id_token_hint=" .. idToken
        sendRedirect(redirectURL)
        return        
    elseif (HTTPRequest.getMethod() == "POST") then
        local requestParams = formsModule.getPostParams(HTTPRequest.getBody())

        local logout_token = requestParams["logout_token"]
        if not logout_token then
            errorResponseSLO("Unable to retrieve logout_token")
            return
        end

        -- need to validate the logout token, similar to validating an id_token
        local logoutTokenValidationResults = validateLogoutToken(issuerConfig, opMetadata, logout_token)

        if not logoutTokenValidationResults["valid"] then
            errorResponseSLO("Invalid logout_token: " .. logoutTokenValidationResults["error"])
            return
        end

        -- if we get this far, then we just call the redis helper to delete either all 
        -- sessions for the user, or if a sid is provided, just that session
        local logoutTokenClaims = logoutTokenValidationResults["jwtClaims"]
        local logoutResult = sloUsingRedis(logoutTokenClaims["sub"], logoutTokenClaims["sid"])
        if not logoutResult then
            errorResponseSLO("Could not find session to logout")
            return
        end

        -- done - just return a 200 response
        HTTPResponse.setStatusCode(200)
        HTTPResponse.setStatusMsg("OK")
        HTTPResponse.setHeader("content-type", "application/json")
        HTTPResponse.setBody('{"status":"ok"}')
        Control.responseGenerated(true)
    else
        errorResponseSLO("Invalid HTTP method")
        return
    end
end


--[[
    Use this for demo purposes only. It will generate and display a curl command that can be used to request
    a sample resource, as protected by the companion oidcresourceserver.lua transformation. It is expected
    that oidc login has already occurred and that the credential is populated with the DPoP keys.
--]]
local function processSampleResourceRequest()

    local tokenType = Session.getCredentialAttribute("token_type")
    if not tokenType then
        errorResponseHTML("Unable to retrieve token_type")
        return
    end
    local accessToken = Session.getCredentialAttribute("access_token")
    if not accessToken then
        errorResponseHTML("Unable to retrieve access_token")
        return
    end

    local dpopProof = nil
    local aznTokenType = "Bearer"
    local htu = getBaseURL() .. "/resource.html"

    if (tokenType == "DPoP") then
        aznTokenType = "DPoP"

        local dpopPublicKeyJWKStr = Session.getSessionAttribute("dpop_public_key")
        if not dpopPublicKeyJWKStr then
            errorResponseHTML("Unable to retrieve DPoP public key from session")
            return
        end
        local dpopPublicKeyJWK = cjson.decode(dpopPublicKeyJWKStr)

        local dpopPrivateKeyJWKStr = Session.getSessionAttribute("dpop_private_key")
        if not dpopPrivateKeyJWKStr then
            errorResponseHTML("Unable to retrieve DPoP private key from session")
            return
        end
        local dpopPrivateKeyJWK = cjson.decode(dpopPrivateKeyJWKStr)

        local dpopAlg = Session.getSessionAttribute("dpop_alg")
        if not dpopAlg then
            errorResponseHTML("Unable to retrieve DPoP alg from session")
            return
        end

        local dpopOptions = {
            keypair = {
                jwkPublicKey = dpopPublicKeyJWK,
                jwkPrivateKey = dpopPrivateKeyJWK,
                publicKey = cryptoLite.jwkToPEM(dpopPublicKeyJWK),
                privateKey = cryptoLite.jwkToPEM(dpopPrivateKeyJWK),
                alg = dpopAlg
            },
            htm = "GET",
            htu = htu,
            access_token = accessToken
        }
        dpopProof = createDPoPProof(dpopOptions)
    end

    local headers = {
        ["Accept"] = "application/json",
        ["Authorization"] = aznTokenType .. " " .. accessToken
    }
    if dpopProof then
        headers["DPoP"] = dpopProof
    end 
    local curlCmd = 'curl -k -v -H "Accept: application/json"'
    curlCmd = curlCmd .. ' -H "Authorization: ' .. aznTokenType .. ' ' .. accessToken .. '"'
    if dpopProof then
        curlCmd = curlCmd .. ' -H "DPoP: ' .. dpopProof .. '"'
    end
    curlCmd = curlCmd .. ' "' .. htu .. '"'

    local htmlContent = [[
<html>
  <head>
    <style>
        .spinner {
            min-width: 48px;
            min-height: 48px;
            background-repeat: no-repeat;
            background-image: url(data:image/gif;base64,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);
        }
    </style>
    <script>
      var url = ']] .. htmlUtils.htmlEncode(htu) .. [[';
      var headers = ]] .. cjson.encode(headers) .. [[;

      function showDiv(id) {
        document.getElementById(id).style.display = "block";
      }

      function hideDiv(id) {
        document.getElementById(id).style.display = "none";
      }

      function clearDiv(id) {
        document.getElementById(id).textContent = '';
      }

      function doFetch() {
        hideDiv("responseContentDiv");
        clearDiv("httpStatusDiv");
        clearDiv("rspBodyDiv");
        showDiv("responseSpinnerDiv");
        let rspStatus = 0;
        fetch(
            url,
            {
                'method': 'GET',
                'headers': headers
            }
        ).then((response) => {
            rspStatus = response.status;
            return response.json();
        }).then((data) => {
            var statusColor = (rspStatus === 200) ? 'green' : 'red';
            var httpStatusDiv = document.getElementById("httpStatusDiv");
            httpStatusDiv.textContent = ''+rspStatus;
            httpStatusDiv.style.color = statusColor;
            var rspBodyDiv = document.getElementById("rspBodyDiv");
            rspBodyDiv.textContent = JSON.stringify(data, null, 2);
            rspBodyDiv.style.color = statusColor;
            hideDiv("responseSpinnerDiv");
            showDiv("responseContentDiv");
        });
      }

      window.addEventListener("load", function() {
        var curlDiv = document.getElementById("curlDiv");
        var curlCmd = 'curl -k -v ';
        Object.keys(headers).forEach(k => {
          curlCmd += '-H "' + k + ': ' + headers[k] + '" ';
        });
        curlCmd += '"' + url + '"';
        curlDiv.textContent = curlCmd;

        document.getElementById("runButton").addEventListener('click', doFetch);
      });
    </script>
  </head>
  <body>
    <h1>Sample resource request</h1>
    <pre><div id="curlDiv"></div></pre>
    <input type="button" id="runButton" value="Run with fetch" />
    <div id="responseDiv">
        <h2>Response</h2>
        <div id="responseSpinnerDiv" class="spinner" style="display:none"></div>
        <div id="responseContentDiv" style="display:none">
            <h3>HTTP Status</h3>
            <div id="httpStatusDiv"></div>
            <h3>Response Body</h3>
            <pre><div id="rspBodyDiv"></div></pre>
        </div>
    </div>
  </body>
</html>    
    ]]
	HTTPResponse.setStatusCode(200)
	HTTPResponse.setStatusMsg("OK")
	HTTPResponse.setBody(htmlContent)
	Control.responseGenerated(true)
end


--[[
    Iterates through all the configured clients and builds a JWKS response
    for any public keys.
--]]
local function processJWKSRequest()
    local jwks = cjson.decode('{"keys":[]}')
    for iname, iconfig in pairs(oidcClientConfig["issuers"]) do
        if iconfig["jwkPublicKey"] then
            -- encode/decode to create a copy
            local kentry = cjson.decode(cjson.encode(iconfig["jwkPublicKey"]))

            -- add use and kid fields for publication in jwks
            kentry["use"] = "sig"
            kentry["kid"] = cryptoLite.generateJWKThumbprint(iconfig["jwkPublicKey"])

            table.insert(jwks["keys"], kentry)
        end
    end
	HTTPResponse.setStatusCode(200)
	HTTPResponse.setStatusMsg("OK")
    HTTPResponse.setHeader("Content-type", "application/json")
	HTTPResponse.setBody(cjson.encode(jwks))
	Control.responseGenerated(true)
end

--[[
        The main entry point
--]]

-- Determine the current URL path to figure out which part of the OIDC flow we are performing
local url = HTTPRequest.getURL()
local method = HTTPRequest.getMethod()

if (string.find(url, "^/oidckickoff")) then
    processKickoffURL()
elseif (string.find(url, "^/oidcredirect/")) then
    processRedirectURL()
elseif (string.find(url, "^/oidcslo")) then
    processSingleLogout()
elseif (string.find(url, "^/sampleresourcerequest")) then
    processSampleResourceRequest()
elseif (string.find(url, "^/oidcjwks")) then
    processJWKSRequest()
else
    -- a misconfiguration
    errorResponseHTML("Unable to determine processing rules for url: " .. url .. " and method: " .. method)
end
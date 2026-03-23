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
    preazn:
      - name: oidcclient_kickoff
        paths: 
          - "/oidckickoff*"
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
request-match = preazn:GET /oidckickoff*
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

--[[
        Config
--]]

-- Note: You can (and should) make this a HTTP transformation secret in configuration. This might be a Kubernetes secret in container deployment.
local clientConfigString = [[
{
    "default_issuer": "myidp_plain",
    "issuers": {
        "myidp_dpop": {
            "op_issuer_uri": "https://REDACTED/oauth2",
            "client_id": "REDACTED",
            "client_secret": "REDACTED",
            "dpop_signing_alg": "RS256",
            "skipTLSVerify": false,
            "preferred_client_auth_method": "client_secret_post",
            "prefer_pushed_authorization_requests": true
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



--[[
        Utility Functions
--]]

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
    Use for returning a HTML error page to the browser
--]]
local function errorResponseHTML(msg)
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
	
	logger.debugLog('errorResponse: ' .. msg)
	HTTPResponse.setStatusCode(403)
	HTTPResponse.setStatusMsg("Bad Request")
	HTTPResponse.setBody(htmlContent)
	
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

local function validateIDToken(issuerConfig, opMetadata, id_token)
    local validationResult = {
        ["valid"] = false,
        ["error"] = "Unknown error"
    }

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
    local tokenResponse = options.tokenResponse
    local idTokenHeader = options.idTokenHeader
    local idTokenClaims = options.idTokenClaims
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
                        table.insert(strArray, logger.dumpAsString(v))
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

    -- if we are using client_secret_post, add the client_secret
    if (issuerConfig["client_auth_method"] == "client_secret_post") then
        paramMap["client_secret"] = issuerConfig["client_secret"]
    end

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

	--local req = httpreq.new_from_uri(tokenEndpoint)
    --local req = httpreq.new_from_uri("https://webhook.site/2eb8fc0d-ee5a-444e-93ed-244dc8765e78")
    local req = httpreq.new_from_uri("https://myidp.ice.ibmcloud.com/oauth2/token")
	
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
    local idTokenValidationResults = validateIDToken(issuerConfig, opMetadata, tokenResponse["id_token"])


    if not idTokenValidationResults["valid"] then
        errorResponseHTML("Invalid ID token: " .. idTokenValidationResults["error"])
        return
    end

    --
    -- Success! We will now remove the session state information, and login
    --
    Session.removeSessionAttribute(stateKey)
    local loginOptions = {
        tokenResponse = tokenResponse, 
        idTokenHeader = idTokenValidationResults["jwtHeader"], 
        idTokenClaims = idTokenValidationResults["jwtClaims"]
    }
    -- if we are using DPoP, include the DPoP keypair such that the private key can be added to the credential
    -- or Session attributes for potential later use
    if (dpopKeyPair) then
        loginOptions["dpopKeyPair"] = dpopKeyPair
    end

    performLogin(loginOptions)
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

    local curlCmd = 'curl -k -v -H "Accept: application/json"'
    curlCmd = curlCmd .. ' -H "Authorization: ' .. aznTokenType .. ' ' .. accessToken .. '"'
    if dpopProof then
        curlCmd = curlCmd .. ' -H "DPoP: ' .. dpopProof .. '"'
    end
    curlCmd = curlCmd .. ' "' .. htu .. '"'

    local htmlContent = '<html><h1>Sample resource request:</h1><pre>' .. htmlUtils.htmlEncode(curlCmd) .. '</pre></html>'
	HTTPResponse.setStatusCode(200)
	HTTPResponse.setStatusMsg("OK")
	HTTPResponse.setBody(htmlContent)
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
elseif (string.find(url, "^/sampleresourcerequest")) then
    processSampleResourceRequest()
else
    -- a misconfiguration
    errorResponseHTML("Unable to determine processing rules for uri: " .. uri .. " and method: " .. method)
end
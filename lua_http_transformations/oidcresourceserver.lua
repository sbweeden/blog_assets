--[[
    A transformation that acts as an OIDC resource server and validates either standard access tokens (via introspect endpoint) or DPoP-based access tokens, including the DPoP-proof JWT.

    Activated in Reverse Proxy config with:


====== IAG example ==========
policies:

  http_transformations:
    preazn:
      - name: oidcresourceserver
        paths: 
          - "/resource.html"
        method: "GET"
        rule: "@oidcresourceserver.lua"
====== END IAG example ==========

====== WebSEAL example ==========
    [http-transformations]
    oidc-resource-server = OIDCResourceServer.lua

    [http-transformations:oidc-resource-server]	
	request-match = preazn:GET /resource.html *
====== END WebSEAL example ==========
--]]

local cjson = require 'cjson'
local httpreq = require 'http.request'
local httpcookie = require 'http.cookie'
local httpheaders = require 'http.headers'
local httputil = require 'http.util'
local tls = require 'http.tls'
local baseutils = require 'basexx'
local digest = require 'openssl.digest'

local logger = require 'LoggingUtils'
local jwtUtils = require 'JWTUtils'
local forms = require 'FormsModule'
local cryptoLite = require "CryptoLite"
local cachedURLRetriever = require 'CachedURLRetriever'
local redisHelper = require 'RedisHelper'

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

local redisClient = nil

-- Constants used in lifetime calculations (in seconds)
local SKEW = 30
local MAX_DPOP_LIFETIME = 120

--[[
    getBaseURL
    Determines best guess of the start of the URL that the browser used to get to us
--]]
local function getBaseURL()
    return "https://" .. HTTPRequest.getHeader("host")
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
end

--[[
	nocase
	Converts a string into a case-insensitive pattern for Lua pattern matching.
	Takes each alphabetic character and replaces it with a character class containing
	both its lowercase and uppercase versions (e.g., "a" becomes "[aA]").
	This allows for case-insensitive string matching when used with string.find().
	
	Parameters:
		s - The input string to convert
	
	Returns:
		A pattern string where each letter is replaced with [lowercase][uppercase]
	
	Example:
		nocase("bearer") returns "[bB][eE][aA][rR][eE][rR]"
--]]
local function nocase(s)
	s = string.gsub(s, "%a", function (c)
		return string.format("[%s%s]", string.lower(c), string.upper(c))
	end)
	return s
end

local function extractLabeledToken(l, s)
	local result = nil
	if (s ~= nil) then
		local pattern = nocase(l) .. "%s+" .. "(.+)"
		local _,_,token = string.find(s, pattern)
		result = token
	end
	return result
end

local function extractBearerToken(s)
	return extractLabeledToken("bearer", s)
end

local function extractDPoPToken(s)
	return extractLabeledToken("dpop", s)
end

local function getDPoPProofJWT()
	return HTTPRequest.getHeader("DPoP")
end

local function introspect(issuerConfig, opMetadata, at)
	local endpoint = opMetadata["introspection_endpoint"]
	local req = httpreq.new_from_uri(endpoint)
	
	-- we are going to use TLS	
	req.ctx = tls.new_client_context()

	-- ignore SSL cert errors - bit sketchy, but better than having to figure out the localhost certificate for the runtime
	req.ctx:setVerify(require "openssl.ssl.context".VERIFY_NONE)
	
	local bodyParams = {}
	bodyParams["client_id"] = issuerConfig["client_id"]
	bodyParams["token"] = at

    if (issuerConfig["client_auth_method"] == "client_secret_basic") then
        req.headers:upsert("authorization", "Basic " .. baseutils.to_base64(issuerConfig["client_id"] .. ':' .. issuerConfig["client_secret"]))
    elseif (issuerConfig["client_auth_method"] == "client_secret_post") then
        bodyParams["client_secret"] = issuerConfig["client_secret"]
    end
	
	req.headers:upsert("content-type", "application/x-www-form-urlencoded")
	req.headers:upsert("accept", "application/json")
	req.headers:upsert(":method", "POST")
	
	-- Use a new cookie store each time - we want our requests to be stateless and 
	-- unrelated to any other invocations.
	-- see: https://daurnimator.github.io/lua-http/0.3/#http.request.cookie_store
	-- NOTE WELL: defaults to a shared store.
	--
	local newCookieStore = httpcookie.new_store()	
	req.cookie_store = newCookieStore
	
	local body = forms.getPostBody(bodyParams)
	req:set_body(body)
	local headers, stream = assert(req:go())

	local httpStatusCode = headers:get ":status"
	-- logger.debugLog("OIDCResourceServer.introspect HTTP response status: " .. httpStatusCode)
	if httpStatusCode == "200" then        
		local rspbody = assert(stream:get_body_as_string())
		if not (rspbody == nil or (not rspbody)) then
			result = cjson.decode(rspbody)
		else
			logger.debugLog("OIDCResourceServer.introspect: no body in HTTP response")
		end
	else
        -- try to get rspbody to see if there is any extra info
        local rspbody = stream:get_body_as_string()
		logger.debugLog("OIDCResourceServer.introspect: invalid HTTP response code: " .. httpStatusCode .. " rspbody: " .. logger.dumpAsString(rspbody))
	end

	return result
end

--[[
    jsonResponse
    Use for returning a generic JSON payload to a client with a 200 OK status

--]]
local function jsonResponse(jObj)
    HTTPResponse.setStatusCode(200)
    HTTPResponse.setStatusMsg("OK")
    HTTPResponse.setHeader("content-type", "application/json")
    HTTPResponse.setBody(cjson.encode(jObj))
    Control.responseGenerated(true)
end

--[[
    errorResponseJSON
    Use for returning a JSON error to the DBSC client

--]]
local function errorResponseJSON(msg)

    local errJSON = {}
    errJSON["error"] = "invalid_token"
	errJSON["error_description"] = msg

    HTTPResponse.setStatusCode(401)
    HTTPResponse.setStatusMsg("Bad Request")
    HTTPResponse.setHeader("content-type", "application/json")
    HTTPResponse.setBody(cjson.encode(errJSON))
    Control.responseGenerated(true)
end

local function resourceResponse(introspectResult, accessToken, dpopProof)
	local responseBody = {}
	responseBody["username"] = introspectResult["preferred_username"]
	responseBody["sub"] = introspectResult["sub"]
	responseBody["token_type"] = introspectResult["token_type"]
	if (accessToken ~= nil) then
		responseBody["access_token"] = accessToken 
	end
	if (dpopProof ~= nil) then
		responseBody["dpop_proof"] = dpopProof 
	end
	jsonResponse(responseBody)
end

local function sha256b64u(str)
	return baseutils.to_url64(digest.new("sha256"):final(str))
end

--[[
	Generate the JWK thumbprint of a public key per https://datatracker.ietf.org/doc/html/rfc7638	
--]]
local function generateJWKThumbprint(jwk)
	local result = nil
	if (jwk ~= nil) then
		local keyOk = true
		-- items in this table are sorted lexographically on purpose
		local sortedRequiredKeyParameters = {}
		local kty = jwk["kty"]
		if (kty == "RSA") then
			table.insert(sortedRequiredKeyParameters, "e")
			table.insert(sortedRequiredKeyParameters, "kty")
			table.insert(sortedRequiredKeyParameters, "n")
		elseif (kty == "EC") then
			table.insert(sortedRequiredKeyParameters, "crv")
			table.insert(sortedRequiredKeyParameters, "kty")
			table.insert(sortedRequiredKeyParameters, "x")
			table.insert(sortedRequiredKeyParameters, "y")
		else
			keyOk = false
			logger.debugLog("generateJWKThumbprint unsupported kty: " .. (kty or "nil"))
		end
		
		local jsonKeyStr = "{"
		if (keyOk) then			
			for index,k in ipairs(sortedRequiredKeyParameters) do
				local kval = jwk[k]
				if (kval ~= nil) then
					jsonKeyStr = jsonKeyStr .. '"' .. k .. '":"' .. kval .. '"'
				else
					keyOk = false
				end
				
				-- append a comma if there are more elements to come
				if (index < #sortedRequiredKeyParameters) then
					jsonKeyStr = jsonKeyStr .. ","
				end
			end
		end
		
		if (keyOk) then
			jsonKeyStr = jsonKeyStr .. "}"			
			result = sha256b64u(jsonKeyStr)
		end
	end
	return result
end

local function nonceInList(lookupKey, nonce)
    -- unfortunately until we have a global key/value cache class provided by IVIA, we cannot do anything here except in the case
    -- where Redis is available. With redis we can create a global cache key entry, using the lookup key
    -- of the jwkThumbprint and a timeout as long as a grant is valid
    if redisHelper.isRedisConfigured() then
        if redisClient == nil then
            redisClient = redisHelper.getRedisClient()
        end
        local redisLookupKey = "DPOP_NONCE_LIST_" .. lookupKey .. "_" .. nonce
        return redisHelper.existsGlobalKey(redisClient, redisLookupKey)
    else
        logger.debugLog("WARNING: no redis available, so there is no DPoP jti validation performed")
    end
    return false
end

local function addNonceToList(lookupKey, nonce)
    -- unfortunately until we have a global key/value cache class provided by IVIA, we cannot do anything here except in the case
    -- where Redis is available. With redis we can create a global cache key entry, using the lookup key
    -- of the jwkThumbprint and a timeout as long as a grant is valid
    if redisHelper.isRedisConfigured() then
        if redisClient == nil then
            redisClient = redisHelper.getRedisClient()
        end
        local redisLookupKey = "DPOP_NONCE_LIST_" .. lookupKey .. "_" .. nonce
        redisHelper.setGlobalKey(redisClient, redisLookupKey, "true", SKEW+MAX_DPOP_LIFETIME)
    else
        logger.debugLog("WARNING: no redis available, so there is no DPoP jti validation performed")
    end
end

local allowedDPoPAlgs = { "RS256", "ES256" }


local function validateDPoPProof(dpopProofJWT, accessToken, cnf)
	
	local result = false

	-- first a basic test to see if it is JWT-like
    local success, decodeResult = pcall(jwtUtils.decode, dpopProofJWT)
    if not success then 
        error("validateDPoPProof: dpopProofJWT does not appear to be a JWT")
    end
    
    local jwtHeaderTable = decodeResult.jwtHeader
    local jwtClaimsTable = decodeResult.jwtClaims

    -- check typ
    if (jwtHeaderTable["typ"] ~= "dpop+jwt") then
        error("validateDPoPProof: typ in header is not dpop+jwt")
    end
					
    -- is there an alg
    local dpopAlg = jwtHeaderTable["alg"]
    if (dpopAlg == nil or not(hasValue(allowedDPoPAlgs, dpopAlg))) then
        error("validateDPoPProof: missing or unsupported alg")
    end

    -- get the dpopKey
    -- one way to do this if you are *only* a resource server is to extract from the header itself
    -- and "trust on first use"
    local dpopKey = jwtHeaderTable["jwk"]
    if (not dpopKey) then
        error("validateDPoPProof: missing or invalid dpop_public_key")
    end
		
    -- use the alg from this key to see if it validates as a JWT, including the nonce check
    local jwtValidateOptions = {
        jwt = dpopProofJWT,
        algorithm = dpopKey.alg,
        key = cryptoLite.jwkToPEM(dpopKey),
        validateExp = false
    }
    local success, validateResults = pcall(jwtUtils.validate, jwtValidateOptions)
    if (not success) then
        error("validateDPoPProof: JWT validation failed: " .. logger.dumpAsString(validateResults))
    end

    -- check that the jwk thumbprint matches the provided cnf
    local jwkThumbprint = generateJWKThumbprint(dpopKey)
    if (jwkThumbprint == nil) then
        error("validateDPoPProof: unable to generate jwkThumbprint")
    end

    if not(cnf ~= nil and cnf["jkt"] ~= nil and cnf["jkt"] == jwkThumbprint) then
        error("validateDPoPProof: JWK thumbprint did not match cnf.jkt")
    end

    -- per https://datatracker.ietf.org/doc/html/rfc9449#section-4.2 
    -- validate jti, htm, htu and iat
    local jwtClaims = validateResults.jwtClaims
    if (not jwtClaims["jti"]) then 
        error("validateDPoPProof: JWT did not contain jti")
    end
    
    if (nonceInList(jwkThumbprint, jwtClaims["jti"])) then
        error("validateDPoPProof: jti replay")
    end
    addNonceToList(jwkThumbprint, jwtClaims["jti"])

    local expectedHTM = HTTPRequest.getMethod()
    if (jwtClaims["htm"] ~= expectedHTM) then
        error("validateDPoPProof: JWT contained invalid htm")
    end

    local expectedHTU = getBaseURL() .. HTTPRequest.getURL()
    if (jwtClaims["htu"] ~= expectedHTU) then
        error("validateDPoPProof: JWT contained invalid htu")
    end

    -- for iat, we have a clock skew of 30 seconds, and a freshness window of 2 minutes
    local now = os.time()
    local iat = jwtClaims["iat"]
    if (not(iat ~= nil and iat <= (now+SKEW) and iat >= (now-SKEW-MAX_DPOP_LIFETIME))) then
        error("validateDPoPProof: JWT contained invalid iat")
    end

    -- exp is optional, but if present we validate it
    local exp = jwtClaims["exp"]
    if not((exp == nil or exp > (now-SKEW))) then
        error("validateDPoPProof: JWT contained invalid exp")
    end

    -- as this is a resource request, require and validate ath
    local ath = jwtClaims["ath"]
    if not(ath ~= nil and ath == cryptoLite.sha256(accessToken)) then
        error("validateDPoPProof: JWT contained invalid ath")
    end

    -- wow, worked
    return true
end

local function checkOIDCResourceServer(issuerConfig)
    local opMetadata = performOPDiscovery(issuerConfig)
    if (not opMetadata) then
        errorResponseJSON("Unable to retrieve OP metadata")
        return
    end
    
    -- make some discovery choices
    updateIssuerConfig(issuerConfig, opMetadata)

    local bearerAccessToken = extractBearerToken(HTTPRequest.getHeader("Authorization"))
    local dpopAccessToken = extractDPoPToken(HTTPRequest.getHeader("Authorization"))
    local dpopProofJWT = getDPoPProofJWT()

    if (bearerAccessToken ~= nil) then
        -- Introspect the access token
        local introspectResult = introspect(issuerConfig, opMetadata, bearerAccessToken)
        if (introspectResult == nil) then
            errorResponseJSON("Access token introspection failed")
            return
        end
            
        if (not(introspectResult["active"] == true)) then
            errorResponseJSON("Token not active")
            return
        end
                
        if (not(string.match(introspectResult["token_type"], nocase("bearer")))) then
            errorResponseJSON("Invalid token_type")
            return
        end

        -- echo back some stuff from the introspection response
        logger.debugLog("Request for protected resource contained valid plain bearer access token!")				
        resourceResponse(introspectResult, bearerAccessToken, nil)

    elseif (dpopAccessToken ~= nil) then
        local introspectResult = introspect(issuerConfig, opMetadata, dpopAccessToken)
        -- perform some DPoP-based checks on the introspected token
        if (introspectResult == nil) then
            errorResponseJSON("DPoP access token introspection failed")
            return
        end

        if (not (introspectResult["active"] == true)) then
            errorResponseJSON("Token not active")
        end
                
        if (not(string.match(introspectResult["token_type"], nocase("DPoP")))) then
            errorResponseJSON("Invalid token_type")
            return
        end
                    
        if (dpopProofJWT == nil) then
            errorResponseJSON("No DPoP Proof")
            return
        end
                    
        local success, validateResult = pcall(validateDPoPProof, dpopProofJWT, dpopAccessToken, introspectResult["cnf"])

        if (not success) then
            errorResponseJSON("Invalid DPoP Proof: " .. validateResult)
            return
        end

        -- echo back some stuff from the introspection response
        logger.debugLog("Request for protected resource contained valid access token and DPoP proof!")
        resourceResponse(introspectResult, dpopAccessToken, dpopProofJWT)
    else
        errorResponseJSON("No bearer or dpop access token")
    end
end


--[[
	MAIN ENTRY POINT STARTS HERE
--]]

-- get opMetadata
local issuerConfig = oidcClientConfig.issuers[oidcClientConfig.default_issuer]
checkOIDCResourceServer(issuerConfig)

--[[
        A multifacted transformation that implements IDP fedcm support

        Activated in Reverse Proxy config with:

        ================
        [http-transformations]
        fedcm = fedcm.lua

        [http-transformations:fedcm]
        request-match = request:GET /.well-known/web-identity *
        request-match = request:GET /fedcm/config.json *
        request-match = preazn:GET /fedcm/accounts *
		request-match = request:GET /fedcm/client_metadata*
		request-match = preazn:POST /fedcm/id_assertion *
		request-match = preazn:POST /fedcm/disconnect *
		request-match = postazn:GET /fedcm/login *
        =============
        
        Also require the SameSite=None attribute on the session cookie for it to be passed in FedCM requests to the accounts and id_assertion endpoints

        ================
        [cookie-attributes]
		PD-S-SESSION-ID = [-unsupported-same-site]SameSite=None
        ================

		Note that the WRP configuration file needs to be updated for configuration used by the STS client. This requires all the following parameters:
		
        ================
		[http-transformations:secrets]
		fedcm_assertion_signing_alg=RS256
		fedcm_assertion_signing_keystore=pdsrv
		fedcm_assertion_signing_cert=fidointerop
        ================

		For the RP to obtain access to the JWKS endpoint, enable that local-application in the IDP (accessible via https://fidointerop.securitypoc.com/jwks)
		Unauthenticated access needs to be enabled to this as well.
		================
		[local-apps]
		jwks = jwks
        ================
--]]

local cjson = require 'cjson'
local logger = require 'LoggingUtils'
local formsModule = require 'FormsModule'
local stsclient = require 'STSClient'

-- a few seconds should really be enough
local FEDCM_ASSERTION_MAX_AGE_SECONDS = 60

local hostname = "fidointerop.securitypoc.com"
local clientList = {}
clientList["1e8697b0-2791-11ef-b4dd-bff0b72b7f0d"]={origin="https://mybox33.asuscomm.com:30443",privacy_policy_url="http://ibm.com/privacy-policy.html",terms_of_service_url="http://ibm.com/terms-of-service.html"}


--[[
    starts_with
    String utility function

--]]
local function starts_with(str, start)
	return str:sub(1, #start) == start
 end
 
--[[
    errorResponse
    Use for returning an error code

--]]
function errorResponseJSON(msg)

    local errJSON = {}
    errJSON["error"] = msg

    HTTPResponse.setStatusCode(400)
    HTTPResponse.setStatusMsg("Bad Request")
    HTTPResponse.setHeader("content-type", "application/json")
    HTTPResponse.setBody(cjson.encode(errJSON))

    Control.responseGenerated(true)
end

--[[
    checkSecFetchDestHeader
    Use for returning an error code

--]]
function checkSecFetchDestHeader()

    local result = false
	local sfd = HTTPRequest.getHeader("Sec-Fetch-Dest");
	if (sfd ~= nil and sfd == 'webidentity') then
	    result = true
	else
		local errorMsg = "Bad or missing Sec-Fetch-Dest header"
		logger.debugLog(errorMsg)
		errorResponseJSON(errorMsg)
	end    
	return result
end

--[[
    checkOriginHeader
    Used to perform origin header checking against the client_id

--]]
function checkOriginHeader(clientID)

    local result = true

	local oh = HTTPRequest.getHeader("Origin");
	local clientConfig = clientList[clientID]
	if (clientConfig == nil or clientConfig['origin'] ~= oh) then
		logger.debugLog("Origin header check failed for client_id: " .. clientID .. " Origin header: " .. oh);
		result = false
	end
	return result
end

--[[
    wellknownResponse
    Return response to the well-known endpoint

--]]
function wellknownResponse()
	HTTPResponse.setHeader("content-type", "application/json")
	HTTPResponse.setStatusCode(200)
	
	local wellknownJSON = {}
	wellknownJSON["provider_urls"] = { "https://" .. hostname .. "/fedcm/config.json" }
	
	HTTPResponse.setStatusMsg("OK")
	HTTPResponse.setBody(cjson.encode(wellknownJSON))
	
	Control.responseGenerated(true)
end


--[[
    configResponse
    Return response to the config.json endpoint

--]]
function configResponse()

    local configJSON = {}
    configJSON["accounts_endpoint"] = "/fedcm/accounts"
    configJSON["id_assertion_endpoint"] = "/fedcm/id_assertion"
    configJSON["login_url"] = "/fedcm/login"
	configJSON["client_metadata_endpoint"] = "/fedcm/client_metadata"


	HTTPResponse.setHeader("content-type", "application/json")
	HTTPResponse.setStatusCode(200)
	
	HTTPResponse.setStatusMsg("OK")
	HTTPResponse.setBody(cjson.encode(configJSON))
	
	Control.responseGenerated(true)
end

--[[
    encodeAsArray
    Assist with json encoding a table to an array that might be empty

--]]
function encodeAsArray(arr)
	if (#arr < 1) then
		return "[]"
	end
	return cjson.encode(arr)
end

--[[
    accountsResponse
    Return response to the accounts endpoint

--]]
function accountsResponse()

    local accountsJSON = {}
	local statusCode = 200
    
    local username = Session.getUsername()
    logger.debugLog("username: " .. username)
    if (username ~= nil and username ~= "unauthenticated") then
    	local userRecord = {}
    	userRecord["id"] = Session.getCredentialAttribute("AZN_CRED_PRINCIPAL_UUID")
    	userRecord["name"] = Session.getCredentialAttribute("AZN_CRED_PRINCIPAL_NAME")
    	userRecord["email"] = Session.getCredentialAttribute("email")
    	accountsJSON = { userRecord }
	else
		statusCode = 401
    end
    

	logger.debugLog("accountsResponse. response status: " .. statusCode .. " body: " .. cjson.encode(accountsJSON))

	HTTPResponse.setHeader("content-type", "application/json")
	HTTPResponse.setStatusCode(statusCode)
	
	HTTPResponse.setStatusMsg("OK")
	local body = '{ "accounts": ' .. encodeAsArray(accountsJSON) .. '}'
	HTTPResponse.setBody(body)
	
	Control.responseGenerated(true)
end


--[[
    clientMetadataResponse
    Return response to the client_metadata endpoint

--]]
function clientMetadataResponse()

    local metadataJSON = {}
	local statusCode = 200

	local qsParams = formsModule.getQueryParams(HTTPRequest.getURL())
    
    if (qsParams ~= nil and qsParams["client_id"] ~= nil and clientList[qsParams["client_id"]] ~= nil) then
		-- Populate privacy policy url and terms of service url if part of clientList metadata
		local ppu = clientList[qsParams["client_id"]]["privacy_policy_url"]
		if (ppu ~= nil) then
			metadataJSON["privacy_policy_url"]  = ppu
		end
		local tsu = clientList[qsParams["client_id"]]["terms_of_service_url"]
		if (tsu ~= nil) then
			metadataJSON["terms_of_service_url"]  = tsu
		end
	else
		statusCode = 401
    end
    
	HTTPResponse.setHeader("content-type", "application/json")
	HTTPResponse.setStatusCode(statusCode)
	
	HTTPResponse.setStatusMsg("OK")
	HTTPResponse.setBody(cjson.encode(metadataJSON))
	
	Control.responseGenerated(true)
end



--[[
    generateAssertionToken
    Uses STS to generate a JWT for the user
--]]
function generateAssertionToken(sub, displayName, email, expiry, nonce)
    local result = nil
    local claims = {}
    claims["sub"] = sub
	claims["displayName"] = displayName
	claims["email"] = email
    claims["exp"] = expiry
	claims["nonce"] = nonce
	claims["iss"] = "https://" .. hostname

    local assertionSigningAlg = Control.getConfig("http-transformations:secrets", "fedcm_assertion_signing_alg")
    local assertionSigningKeyStore = Control.getConfig("http-transformations:secrets", "fedcm_assertion_signing_keystore")
    local assertionSigningCert = Control.getConfig("http-transformations:secrets", "fedcm_assertion_signing_cert")

    -- Note that base token includes claims, and key to sign with
    local baseToken = '<stsuuser:STSUniversalUser xmlns:stsuuser="urn:ibm:names:ITFIM:1.0:stsuuser">' ..
        '<stsuuser:Principal/>' ..
        '<stsuuser:AttributeList/>' ..
        '<stsuuser:ContextAttributes>' ..
        '<stsuuser:Attribute name="claim_json" type="urn:com:ibm:JWT">' ..
        '<stsuuser:Value>' .. cjson.encode(claims) .. '</stsuuser:Value>' ..
        '</stsuuser:Attribute>' ..
        '<stsuuser:Attribute name="signing.alg" type="urn:com:ibm:JWT">' ..
        '<stsuuser:Value>' .. assertionSigningAlg .. '</stsuuser:Value>' ..
        '</stsuuser:Attribute>' ..
        '<stsuuser:Attribute name="signing.db" type="urn:com:ibm:JWT">' ..
        '<stsuuser:Value>' .. assertionSigningKeyStore .. '</stsuuser:Value>' ..
        '</stsuuser:Attribute>' ..
        '<stsuuser:Attribute name="signing.cert" type="urn:com:ibm:JWT">' ..
        '<stsuuser:Value>' .. assertionSigningCert .. '</stsuuser:Value>' ..
        '</stsuuser:Attribute>' ..
        '</stsuuser:ContextAttributes>' ..
        '</stsuuser:STSUniversalUser>'

    local issuerAddress = "http://issuer/stsuu"
    local appliesToAddress = "http://appliesto/jwt"
    local requestType = "http://schemas.xmlsoap.org/ws/2005/02/trust/Validate"

        
    local stsResponse = stsclient.callSTS(requestType, nil, issuerAddress, appliesToAddress, nil, baseToken)
    if (stsResponse ~= nil) then
        logger.debugLog("generateAssertionToken: stsResponse: " .. stsResponse)
        -- dirty find here to extract the JWT
        local _,_,jwtStr = string.find(stsResponse, "<wss:BinarySecurityToken [^>]+>([A-Za-z0-9%_%-%.]+)</wss:BinarySecurityToken>")
        if (jwtStr ~= nil) then
            logger.debugLog("generateAssertionToken: received JWT: " .. jwtStr)
            result = jwtStr
        else
            logger.debugLog("generateAssertionToken: no JWT in STS response")
        end
    else
        logger.debugLog("generateAssertionToken: no STS response")
    end

    return result
end



--[[
    assertionResponse
    Return response to the id_assertion endpoint

--]]
function assertionResponse()

    local assertionJSON = {}
	local statusCode = 200

	local formParams = formsModule.getPostParams(HTTPRequest.getBody())

	local clientID = formParams["client_id"]
	local accountID = formParams["account_id"]
	local nonce = formParams["nonce"]
	local disclosureTextShown = formParams["disclosure_text_shown"]
	local isAutoSelected = formParams["is_auto_selected"]

	local originHeader = HTTPRequest.getHeader("Origin")

	local username = Session.getUsername()
	local displayName = Session.getCredentialAttribute("displayName")
	local email = Session.getCredentialAttribute("email")
	local uid = Session.getCredentialAttribute("AZN_CRED_PRINCIPAL_UUID")

	local debugJSON = {}
	debugJSON["clientID"] = clientID
	debugJSON["accountID"] = accountID
	debugJSON["nonce"] = nonce
	debugJSON["disclosureTextShown"] = disclosureTextShown
	debugJSON["isAutoSelected"] = isAutoSelected
	debugJSON["username"] = username
	debugJSON["uid"] = uid
	debugJSON["originHeader"] = originHeader

	logger.debugLog("assertionResponse.debugJSON: " .. cjson.encode(debugJSON))


	-- TODO: Include origin header checking, clientID checking and break error conditions down
	local errorCode = nil
	if (checkOriginHeader(clientID)) then
		if (username ~= nil and username ~= "unauthenticated") then 
			if (uid ~= nil and uid == accountID) then
				-- all ok - build the assertion
				local expireAtMilliseconds = (os.time() + FEDCM_ASSERTION_MAX_AGE_SECONDS)*1000
				local tokenValue = generateAssertionToken(username, displayName, email, expireAtMilliseconds, nonce)
				assertionJSON["token"] = tokenValue
			else
				errorCode = "invalid_request"
				logger.debugLog("assertionResponse: invalid account_id")
			end
		else
			errorCode = "invalid_request"
			logger.debugLog("assertionResponse: user not authenticated")
		end
	else
		errorCode = "invalid_request"
		logger.debugLog("assertionResponse: bad origin")
	end

	-- build error message if we have an error
	if (errorCode ~= nil) then
		statusCode = 401
		assertionJSON["error"] = {
			code = errorCode,
			url = "htps://" .. hostname .. "/error"
		}
    end
    
    logger.debugLog("assertionResponse. response status: " .. statusCode .. " body: " .. cjson.encode(assertionJSON))
    
	-- return response
	HTTPResponse.setHeader("content-type", "application/json")
	HTTPResponse.setHeader("Access-Control-Allow-Origin", originHeader)
	HTTPResponse.setHeader("Access-Control-Allow-Credentials", "true")
	HTTPResponse.setStatusCode(statusCode)
	
	HTTPResponse.setStatusMsg("OK")
	HTTPResponse.setBody(cjson.encode(assertionJSON))
	
	Control.responseGenerated(true)
end


--[[
    disconnectResponse
    Return response to the disconnect endpoint

--]]
function disconnectResponse()

    local disconnectJSON = {}
	local statusCode = 200

	local formParams = formsModule.getPostParams(HTTPRequest.getBody())

	local clientID = formParams["client_id"]
	local accountHint = formParams["account_hint"]

	local originHeader = HTTPRequest.getHeader("Origin")

	-- TODO - Implement the disconnect logic
	local errorCode = nil
	if (checkOriginHeader(clientID)) then
		if (username ~= nil and username ~= "unauthenticated") then
			if (username == accountHint) then
				-- all ok - build the disconnect response
				disconnectJSON["account_id"] = username
			else
				errorCode = "invalid_request"
				logger.debugLog("disconnectResponse: invalid account_id")
			end
		else
			errorCode = "invalid_request"
			logger.debugLog("disconnectResponse: user not authenticated")
		end
	else
		errorCode = "invalid_request"
		logger.debugLog("disconnectResponse: bad origin")
	end

	-- build error message if we have an error
	if (errorCode ~= nil) then
		statusCode = 401
		assertionJSON["error"] = {
			code = errorCode,
			url = "htps://" .. hostname .. "/error"
		}
    end
    
	-- return response
	HTTPResponse.setHeader("content-type", "application/json")
	HTTPResponse.setHeader("Access-Control-Allow-Origin", originHeader)
	HTTPResponse.setHeader("Access-Control-Allow-Credentials", "true")
	HTTPResponse.setStatusCode(statusCode)
	
	HTTPResponse.setStatusMsg("OK")
	HTTPResponse.setBody(cjson.encode(disconnectJSON))
	
	Control.responseGenerated(true)
end

--[[
    loginCompleteResponse
    Return response to close the login dialog and set login status to "logged-in"

--]]
function loginCompleteResponse()
	logger.debugLog("loginCompleteResponse called")

	-- Need to remove this cookie because we are transforming from a ficticous resource and WebSEAL will try and resolve using the value of the IV_JCT cookie
	HTTPRequest.removeCookie("IV_JCT")

	-- Note - we only return a response if the user has logged in. This should be the case if the postazn transformation stage is used
	local username = Session.getUsername()
	if (username ~= nil and username ~= "unauthenticated") then
		HTTPResponse.setStatusCode(200)
		HTTPResponse.setStatusMsg("OK")
		HTTPResponse.setHeader("content-type", "text/html")
		HTTPResponse.setHeader("Set-Login", "logged-in")
		HTTPResponse.setBody('<html><head><script type="text/javascript">console.log("Calling IdentityProvider.close()"); IdentityProvider.close();</script></head><body>One moment...</body></html>')
		Control.responseGenerated(true)
	end
end


--[[
    Main logic starts here
--]]

local u = HTTPRequest.getURL()

logger.debugLog("The URL is: " .. u)
logger.debugLog(logger.dumpAsString(Control.dumpContext()))

if (u == "/.well-known/web-identity") then
	wellknownResponse()
elseif (u == "/fedcm/config.json") then
	if (checkSecFetchDestHeader()) then
		configResponse()
	end
elseif (u == "/fedcm/accounts") then
	if (checkSecFetchDestHeader()) then
		accountsResponse()
	end
elseif (starts_with(u, "/fedcm/client_metadata")) then
	clientMetadataResponse()
elseif (u == "/fedcm/id_assertion") then
	if (checkSecFetchDestHeader()) then
		assertionResponse()
	end
elseif (u == "/fedcm/disconnect") then
	if (checkSecFetchDestHeader()) then
		disconnectResponse()
	end
elseif (u == "/fedcm/login") then
	loginCompleteResponse()
else
	local errorMsg = "Configuration error: Unknown URL" 
	logger.debugLog(errorMsg)
	errorResponseJSON(errorMsg)
end

--[[
	Calls ISVA STS via HTTP client for token issue/validation.
	
	Note that the WRP configuration file needs to be updated for configuration used by the STS client. This requires all the following parameters:
	
	[http-transformations:secrets]
	sts-endpoint=https://localhost/TrustServer/SecurityTokenService
	ba-user-id=easuser
	ba-user-password=passw0rd
--]]

local STSClient = {}

local baseutils = require 'basexx'
local cjson = require 'cjson'
local httpreq = require 'http.request'
local httpheaders = require 'http.headers'
local httputil = require 'http.util'
local tls = require 'http.tls'
local logger = require 'LoggingUtils'

function includeIfNotNil(elem, starttag, endtag)
	local result = ''
	if elem ~= nil then
		result = starttag .. elem .. endtag
	end
	return result
end

--[[
	Calls the STS. The tokenType and stsClaims are optional (can be nil) but all other parameters are required
--]]
function STSClient.callSTS(requestType, tokenType, issuerAddress, appliesToAddress, stsClaims, baseToken)
	local result = nil
	
	-- prepare the request body
	local body = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Header/><soapenv:Body><wst:RequestSecurityToken>'
		.. '<wst:RequestType>'
		.. requestType 
		.. '</wst:RequestType>'
		.. includeIfNotNil(tokenType, '<wst:TokenType>', '</wst:TokenType>')
		..'<wst:Issuer><wsa:Address>'
		.. issuerAddress
		.. '</wsa:Address></wst:Issuer><wsp:AppliesTo><wsa:EndpointReference><wsa:Address>'
		.. appliesToAddress
		.. '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>'
		.. includeIfNotNil(stsClaims, '<wst:Claims>', '</wst:Claims>')
		.. '<wst:Base>'
		.. baseToken
	    .. '</wst:Base>'
	    .. '</wst:RequestSecurityToken></soapenv:Body></soapenv:Envelope>'
	    
	-- logger.debugLog('STSClient.callSTS request body: ' .. body)

	local endpoint = Control.getConfig("http-transformations:secrets", "sts-endpoint")
	local bauser = Control.getConfig("http-transformations:secrets", "ba-user-id")
	local bapassword = Control.getConfig("http-transformations:secrets", "ba-user-password")
	
	local req = httpreq.new_from_uri(endpoint)
	
	-- update request HTTP headers
	-- This includes setting the BA header, content-type, accept, and the HTTP method
	-- note use of upsert here (rather than append) to replace any defaults
	req.headers:upsert("authorization", "Basic " .. baseutils.to_base64(bauser .. ':' .. bapassword))
	req.headers:upsert("content-type", "text/xml")
	req.headers:upsert("accept", "text/xml")
	req.headers:upsert(":method", "POST")
	

	-- we are going to use TLS	
	req.ctx = tls.new_client_context()
	
	-- ignore SSL cert errors - bit sketchy, but better than having to figure out the localhost certificate for the runtime
	req.ctx:setVerify(require "openssl.ssl.context".VERIFY_NONE)
	
	req:set_body(body)
	local headers, stream = assert(req:go())
	
	local httpStatusCode = headers:get ":status"
	-- logger.debugLog("STSClient.callSTS HTTP response status: " .. httpStatusCode)
	if httpStatusCode == "200" then
		local rspbody = assert(stream:get_body_as_string())
		if not (rspbody == nil or (not rspbody)) then
			result = rspbody
		else
			logger.debugLog("STSClient.callSTS: no body in HTTP response")
		end
	else
		logger.debugLog("STSClient.callSTS: STS returned invalid HTTP response code: " .. httpStatusCode)
	end
	
	return result
end

return STSClient

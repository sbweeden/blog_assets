--[[
    A transformation that exercises recaptchav3 (https://developers.google.com/recaptcha/docs/v3)
	
	The GET request serves a HTML page with client-side instrumentation for recaptchav3
	
	The POST request calls Google to get the evaluated risk score and display it in HTML back to the client.
	
	Obviously this is not what you would normally do with a risk score, but gives you idea of the basic mechanics of the mechanism.
		
	An alternative course of action might be to set the risk score value in an injected REQUEST HTTP Header which could be consumed by an access policy evaluation. 

    Activated in Reverse Proxy config with:

    ================
    [http-transformations]
    recaptchav3 = recaptchav3.lua

    [http-transformations:recaptchav3]	
	request-match = preazn:GET /recaptchav3 *
	request-match = preazn:POST /recaptchav3 *
	=============
--]]

local httpreq = require 'http.request'
local httputil = require 'http.util'
local httpcookie = require 'http.cookie'
local tls = require 'http.tls'
local logger = require 'LoggingUtils'
local formsModule = require 'FormsModule'

--
-- From your Google config for recapthca
--
--local siteKey = "REDACTED"
--local secretKey = "REDACTED"

--
-- Utility function to return a success response with pre-html encoded html content
--
local function pageResponseHTML(html)
    HTTPResponse.setStatusCode(200)
    HTTPResponse.setStatusMsg("OK")
    HTTPResponse.setBody(html)

    Control.responseGenerated(true)
end

--
-- Serve the most basic page imaginable which contains recaptchav3 instrumentation
--
local function servePage()
	local bodyContent = ''
	bodyContent = (bodyContent .. [[
<html>
<head>
    <script src="https://www.google.com/recaptcha/api.js"></script>
	<script>
	   function onSubmit(token) {
		 let myForm = document.getElementById("demo-form");
		 myForm.recaptchav3Token.value = token;
		 console.log("token: " + token);
	     myForm.submit();
	   }
	 </script>
</head>
<body>
	Recaptchav3 test page. Press the button.
	<form id="demo-form" method="POST" action="/recaptchav3">
		<input type="hidden" name="recaptchav3Token" value="" />
		<button class="g-recaptcha" 
	        data-sitekey="reCAPTCHA_site_key" 
	        data-callback='onSubmit' 
	        data-action='submit'>Submit</button>
	</form>
</body>
</html>
	]])
	bodyContent = string.gsub(bodyContent, "reCAPTCHA_site_key", siteKey)
	pageResponseHTML(bodyContent)
end

--
-- Calculate risk score and return a page containing it
--
function processPage()	
	local postParams = formsModule.getPostParams(HTTPRequest.getBody())

	if (postParams ~= nil and postParams["recaptchav3Token"] ~= nil) then
		--
		-- Make call to Google to get risk assessment
		--
		local bodyParams = {}
		bodyParams["secret"] = secretKey
		bodyParams["response"] = postParams["recaptchav3Token"]
		-- should do better validation and parsing of this header first
		if (HTTPRequest.getHeader("X-Forwarded-For") ~= nil) then
			bodyParams["remoteip"] = HTTPRequest.getHeader("X-Forwarded-For")
		end
		
		local req = httpreq.new_from_uri("https://www.google.com/recaptcha/api/siteverify")
		
		req.ctx = tls.new_client_context()
		
		-- ignore SSL cert errors - TODO - fix this by describing how to do cert trust properly
		req.ctx:setVerify(require "openssl.ssl.context".VERIFY_NONE)

		req.headers:upsert("content-type", "application/x-www-form-urlencoded")
		req.headers:upsert("accept", "application/json")
		req.headers:upsert(":method", "POST")	
		
		
		
		-- no state in these calls, so use a new cookie store each request
		local newCookieStore = httpcookie.new_store()	
		req.cookie_store = newCookieStore

		local body = formsModule.getPostBody(bodyParams)
		req:set_body(body)
		-- because the body we set is greater than 1024 chars and we do not want to use chunked encoding
		-- remove the expect header that lua-http automatically inserted (see: https://github.com/daurnimator/lua-http/blob/master/http/request.lua#L342)
		-- I found that if I don't do this, the req:go() call below hangs forever
		req.headers:delete("expect")
		
		local headers, stream = assert(req:go())
		
		--
		-- If call worked, return risk assessment as HTML page to client, otherwise indicate error
		--
		local httpStatusCode = headers:get ":status"
		if httpStatusCode == "200" then
			--
			-- typically returns something like
			--
			-- { "success": true, "challenge_ts": "2025-05-23T04:45:17Z", "hostname": "your_hostname.com", "score": 0.9, "action": "submit" }
			--
			local rspbody = assert(stream:get_body_as_string())
			if not (rspbody == nil or (not rspbody)) then
				-- this really should be html encoded
				pageResponseHTML(rspbody)
			else
				pageResponseHTML("processPage: no body in HTTP response")
			end
		else
			pageResponseHTML("processPage received invalid HTTP response code from Google: " .. httpStatusCode)
		end
		
		
	else
		pageResponseHTML("processPage did not receive recaptchav3Token")
	end
end

if (HTTPRequest.getMethod() == "GET") then
	servePage()
elseif (HTTPRequest.getMethod() == "POST") then
	processPage()
else
	pageResponseHTML('Unsupported method: ' .. HTTPRequest.getMethod())
end

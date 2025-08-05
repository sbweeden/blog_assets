--[[
    A transformation that exercises recaptchav3 (https://developers.google.com/recaptcha/docs/v3)
	
	The POST request expects a recaptchav3Token post body parameter and calls Google to get the evaluated risk score. 
	If the risk score is less than a given threshold, a page is returned to the browser saying denied (i.e. bot detected). 
	If the risk score is greater than or equal to the threshold, then no action is taken and the request is allowed to proceed.
		
	This transformation could be appled to the POST of any page which has been instrumented to include recaptchav3 processing
	and include the recaptchav3Token post parameter in the payload, however in particular it has been developed for and tested
	with the WebSEAL login.html page for processing forms-based username/password login. The idea here is that this scenario
	would be useful in performing bot detection of a credential stuffing attack.

    Activated in Reverse Proxy config with:

    ================
    [http-transformations]
	recaptchav3_forms_login = recaptchav3_forms_login.lua

	[http-transformations:recaptchav3_forms_login]
	request-match = request:POST /pkmslogin.form *
	=============
	
	Note that only the "request" phase of Lua HTTP transformations can be used when intercepting requests to /pkmslogin.form
	
	Required utility Lua rules (LoggingUtils and FormsLogin) can be found at 
	https://github.com/sbweeden/blog_assets/tree/master/lua_http_transformations
	
	To instrument the login.html page for recaptchav3, the following changes need to be made.
	
	1. Update the content-security-policy response header (if you are using one) to allow src to be included from Google, and for 
	the necessary framing and connection settings. These were "discovered" by watching the browser console and correcting errors as 
	they showed up when developing the solution.
	
	Eg in WebSEAL config file the following updated CSP setting works:
	
	[acnt-mgt]
	http-rsp-header = content-security-policy:TEXT{default-src 'self'; frame-ancestors 'self'; form-action 'self'; script-src 'self' https://www.google.com/recaptcha/api.js https://www.gstatic.com/recaptcha/; frame-src https://www.google.com/; connect-src 'self' https://www.google.com/recaptcha/;}
	
	2. Create a new file in the WebSEAL management pages pkmspublic/login_recaptchav3.js with contents below (UPDATE the YOUR_SITE_KEY value in your file).
	If you have customized the login page, you may need to change the logic for locating the submit button within the login form, however the example
	below will work with the out-of-the-box login.html shipped with IBM Identity Verify Access.
	
	//
	// Start login_recaptchav3.js
	//
	
	// Update this from your Google recaptchav3 configuration
	let siteKey = "YOUR_SITE_KEY";
	
	window.addEventListener('load', function() {
		let pkmsloginFormsArray = Array.from(document.forms).filter((x) => x.action.endsWith('/pkmslogin.form'));
		if (pkmsloginFormsArray.length == 1) {
			// override what happens on pressing login form submit button to run recaptchav3 then submit form
			let submitButton = pkmsloginFormsArray[0].querySelector(".submitButton");
			if (submitButton != null) {
				submitButton.addEventListener("click", (e) => {
					e.preventDefault();
					grecaptcha.ready(function() {
				    	grecaptcha.execute(siteKey, {action: 'submit'})
				    	.then((token) => {
				              // Include token in hidden field in form submit
							  let recaptchav3Token = document.createElement("input");
							  recaptchav3Token.setAttribute("type", "hidden");
							  recaptchav3Token.setAttribute("name", "recaptchav3Token");
							  recaptchav3Token.setAttribute("value", token);
							  let loginForm = Array.from(document.forms).filter((x) => x.action.endsWith('/pkmslogin.form'))[0];
							  loginForm.appendChild(recaptchav3Token);
				              loginForm.submit();
				        }).catch((e) => {
				        	console.log("Got exception calling recaptchav3: " + e);
				        });
				    });
				});
			}
		}
	});
	//
	// End login_recaptchav3.js
	//
	
	
	3. In the <head> section of your WebSEAL login.html, include both the Google recaptcha API script, and the login_recaptchav3.js script
	being sure to also update the YOUR_SITE_KEY value as well. The site key value has to be updated both in the JS file described above, and here
	when including the api.js script from Google, as well as within this Lua file (3 locations total). The site secretKey value
	should ONLY be updated here in this Lua file (i.e. server-side).
	
	<script src="https://www.google.com/recaptcha/api.js?render=YOUR_SITE_KEY"></script>
	<script src="%PKMSPUBLIC%login_recaptchav3.js"></script>

	
	
--]]

local httpreq = require 'http.request'
local httputil = require 'http.util'
local httpcookie = require 'http.cookie'
local tls = require 'http.tls'
local x509    = require "openssl.x509"
local cjson = require 'cjson'
local logger = require 'LoggingUtils'
local formsModule = require 'FormsModule'

--
-- Risk score threshold. Scores below this number will result in a denied page.
--
local THRESHOLD = 0.5



--
-- From your Google config for recapthca
--
--local siteKey = "YOUR_SITE_KEY"
--local secretKey = "YOUR_SITE_SECRET_KEY"

-- used for testing only
local ignoreServerSSLCertificates = false

--
-- X509 trust root for Google TLS connection
-- discovered other certs with: 
--	keytool -printcert -rfc -sslserver www.google.com
--
local GlobalSignRootCA = [[
-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG
A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv
b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw
MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT
aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ
jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp
xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp
1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG
snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ
U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8
9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B
AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz
yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE
38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP
AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad
DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME
HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==
-----END CERTIFICATE-----
]]

--
-- Utility function to return a page response with pre-html encoded html content
--
local function pageResponseHTML(statusCode, statusMsg, html)
    HTTPResponse.setStatusCode(statusCode)
    HTTPResponse.setStatusMsg(statusMsg)
    HTTPResponse.setBody(html)

    Control.responseGenerated(true)
end

local function pageResponse400(html)
	pageResponseHTML(400, "Bad request", html)
end

local function pageResponse500(html)
	pageResponseHTML(500, "Server error", html)
end


--
-- Calculate risk score and either let the request proceed, or return a denied page
-- If the recaptchav3 token is not found, an error page is returned.
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
		
		logger.debugLog("recaptchav3 invoked with params: " .. logger.dumpAsString(bodyParams))
		
		local req = httpreq.new_from_uri("https://www.google.com/recaptcha/api/siteverify")
		
		local myctx = tls.new_client_context() 
		
		
		if (ignoreServerSSLCertificates) then
			myctx:setVerify(require "openssl.ssl.context".VERIFY_NONE)
		else
			myctx:setVerify(require "openssl.ssl.context".VERIFY_PEER)
			myctx:getStore():add(x509.new(GlobalSignRootCA))
		end
		
		req.ctx = myctx
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
		-- Required, otherwise the req:go() call below hangs forever
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
				logger.debugLog("Received evaluation response: " .. rspbody)
				
				-- check the score
				local rspJSON = cjson.decode(rspbody)
				if (rspJSON["success"]) then
					if (rspJSON["score"] < THRESHOLD) then
						-- this really should be html encoded
						pageResponse400('Bot detected')
					else
						-- no action needed - human detected
					end
				else
					pageResponse400("processPage: did not receive successful response from recaptchav3 evaluation")
				end
			else
				pageResponse500("processPage: no body in HTTP response")
			end
		else
			pageResponse500("processPage: received invalid HTTP response code from Google: " .. httpStatusCode)
		end
	else
		pageResponse400("processPage: did not receive recaptchav3Token")
	end
end

--
-- The main entry point of the transformation
--
if (HTTPRequest.getMethod() == "POST") then
	processPage()
else
	pageResponse400('Unsupported method: ' .. HTTPRequest.getMethod())
end

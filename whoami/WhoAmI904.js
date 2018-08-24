importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.STSUniversalUser);
importClass(Packages.com.tivoli.am.fim.base64.BASE64Utility);
importPackage(Packages.com.ibm.security.access.httpclient);

/**
 * Utility to get the username from the the Infomap context
 */
function getInfomapUsername() {
	// get username from already authenticated user
	var result = context.get(Scope.REQUEST,
			"urn:ibm:security:asf:request:token:attribute", "username");
	IDMappingExtUtils.traceString("username from existing token: " + result);

	// if not there, try getting from session (e.g. UsernamePassword module)
	if (result == null) {
		result = context.get(Scope.SESSION,
				"urn:ibm:security:asf:response:token:attributes", "username");
		IDMappingExtUtils.traceString
	}
	return result;
}

/**
 * Utility to html encode a string
 */ 
function htmlEncode(str) {
   	return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function stsuuAttributeContainerToJSON(ac) {
	var result = null;
	if (ac != null) {
		result = [];
		for (var ai = ac.getAttributeIterator(); ai.hasNext(); ) {
			var aObj = {};
			var a = ai.next();
			var name = a.getName();
			var nickName = a.getNickname();
			var type = a.getType();
			var values = a.getValues();
			if (name != null && name.length() > 0) {
				aObj["name"] = ''+name;
			}
			if (nickName != null && nickName.length() > 0) {
				aObj["nickname"] = ''+nickName;
			}
			if (type != null && type.length() > 0) {
				aObj["type"] = ''+type;
			}
			if (values != null && values.length > 0) {				
				aObj["values"] = [];
				for (var i = 0; i < values.length; i++) {
					aObj["values"].push(''+values[i]);
				}
			}
			result.push(aObj);
		}
	}
	return result;
}

function stsuuGroupToJSON(g) {
	var result = null;
	if (g != null) {
		result = {};
		result["name"] = ''+g.getName();
		result["type"] = ''+g.getType();
		result["attributes"] = stsuuAttributeContainerToJSON(g);
	}
	return result;
}

function stsuuToJSON(stsuu) {
	var result = null;
	if (stsuu != null) {
		result = {};
		var attrsObj = stsuuAttributeContainerToJSON(stsuu.getPrincipalAttributeContainer());
		if (attrsObj != null) {
			result["Principal"] = attrsObj;	
		}
		attrsObj = stsuuAttributeContainerToJSON(stsuu.getAttributeContainer());
		if (attrsObj != null) {
			result["AttributeList"] = attrsObj;	
		}
		attrsObj = stsuuAttributeContainerToJSON(stsuu.getContextAttributesAttributeContainer());
		if (attrsObj != null) {
			result["ContextAttributes"] = attrsObj;	
		}
		attrsObj = stsuuAttributeContainerToJSON(stsuu.getRequestSecurityTokenAttributeContainer());
		if (attrsObj != null) {
			result["RequestSecurityToken"] = attrsObj;	
		}
		if (stsuu.getNumberOfGroups() > 0) {
			var groupArray = [];
			for (var gi = stsuu.getGroups(); gi.hasNext();) {
				var g = gi.next();
				groupArray.push(stsuuGroupToJSON(g));
			}
			result["Groups"] = groupArray;
		}
	}
	return result;
}

function callSTS(endpoint, bauser, bapassword, issuerAddress, appliesToAddress, requestType, tokenType, baseToken) {
	
	var result = null;
	
	// tokenType is optional
	var tokenTypeElement = '';
	if (tokenType != null) {
		tokenTypeElement = '<wst:TokenType>' + tokenType + '</wst:TokenType>';
	}
	
	// build the WS-Trust 1.2 RST
	var soapRequestBody = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Header/><soapenv:Body><wst:RequestSecurityToken><wst:RequestType>'
		+ requestType 
		+ '</wst:RequestType><wst:Issuer><wsa:Address>'
		+ issuerAddress
		+ '</wsa:Address></wst:Issuer><wsp:AppliesTo><wsa:EndpointReference><wsa:Address>'
		+ appliesToAddress
		+ '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>'
		+ tokenTypeElement
		+ '<wst:Base>'
		+ baseToken
	    + '</wst:Base></wst:RequestSecurityToken></soapenv:Body></soapenv:Envelope>';
	
	// connection properties
	var headers = new Headers();
	headers.addHeader("Content-Type", "text/xml");
	var httpsTrustStore = 'rt_profile_keys';
	
	/**
	 * httpPost(String url, Map headers, String body,String httpsTrustStore,
	 * String basicAuthUsername,String basicAuthPassword, String
	 * clientKeyStore,String clientKeyAlias);
	 */
	var hr = HttpClient.httpPost(endpoint, headers, soapRequestBody, httpsTrustStore, bauser, bapassword, null, null);
	if (hr != null) {
		var code = hr.getCode(); // this is int
		var body = hr.getBody(); // this is java.lang.String

		IDMappingExtUtils.traceString("code: " + code);
		IDMappingExtUtils.traceString("body: " + body);
		
		// sanity check the response code and body - this is "best-effort"
		if (code != 200) {
			IDMappingExtUtils.throwSTSException("Bad response code calling auxilary STS chain: " + code);
		}
		var simpleRSTRPattern = ".*<wst:RequestedSecurityToken>.*</wst:RequestedSecurityToken>.*";
		if (!body.matches(simpleRSTRPattern)) {
			IDMappingExtUtils.throwSTSException("Bad response body calling auxilary STS chain: " + body);
		}
		
		// retrieve the requested security token from the response body
		result = body.replaceFirst(".*<wst:RequestedSecurityToken>", "").replaceFirst("</wst:RequestedSecurityToken>.*", "").replaceAll("&gt;", ">").replaceAll("&lt;", "<");
	}

	return result;
}

// infomap that returns a page indicating if you are authenticated and who you are
var username = getInfomapUsername();

// Now exchange ivcreds for an STSUU and prepare a JSON response
var userCredJSONStr = null;
if (true /* username != null */) {
	var credPrefix = 'Version=1, ';
	var ivcreds = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:header", "iv-creds");
	if (ivcreds.startsWith(credPrefix)) {
		ivcreds = ivcreds.substring(credPrefix.length);
	}
	// wrap in an XML object ready for exchange
	var ivcredsStr = "<wss:BinarySecurityToken wsu:Id=\"uuid99785f92-0124-1282-a937-cf52545c78b4\""
			+ " xmlns:itam=\"urn:ibm:names:ITFIM:5.1:accessmanager\""
			+ " xmlns:wss=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\""
			+ " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\""
			+ " EncodingType=\"http://ibm.com/2004/01/itfim/base64encode\""
			+ " ValueType=\"http://ibm.com/2004/01/itfim/ivcred\">"
			+ ivcreds
			+ "</wss:BinarySecurityToken>";
	
	// exchange for STSUU
	var endpoint = "https://localhost/TrustServer/SecurityTokenService";
	var bauser = "easuser";
	var bapassword = "passw0rd"; // this is the default - you may need to change it
	var issuerAddress = "http://issuer/ivcred";
	var appliesToAddress = "http://appliesto/stsuu";
	var requestType = "http://schemas.xmlsoap.org/ws/2005/02/trust/Validate";
	var tokenType = null;
	var baseToken = ivcredsStr;
	var res = callSTS(endpoint, bauser, bapassword, issuerAddress, appliesToAddress, requestType, tokenType, baseToken);
			
	if (res != null) {
		var stsuu = new STSUniversalUser();
		stsuu.fromXML(res);
		IDMappingExtUtils.traceString("got result: " + stsuu.toString());
		
		// clear stuff we don't want to send back
		stsuu.getRequestSecurityTokenAttributeContainer().clear();
		stsuu.getContextAttributesAttributeContainer().clear();
		
		// convert to JSON
		userCredJSONStr = JSON.stringify(stsuuToJSON(stsuu));
	} else {
		IDMappingExtUtils.throwSTSException("An error occurred invoking the STS: " + res.errorMessage);
	}
}

/*
 * Now return the page 
 */
page.setValue("/authsvc/authenticator/whoami/whoami.html");
macros.put("@AUTHENTICATED@", ''+(username != null));
macros.put("@USERNAME@", (username != null ? htmlEncode(username) : ""));
// we use base64 encoding of the utf-8 bytes of the JSON string to avoid any extended character encoding issues
macros.put("@USER_CRED_JSON@", (userCredJSONStr != null ? userCredJSONStr : ""));

// we never actually perform a login with this infomap
success.setValue(false);

importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.fedmgr2.trust.util.LocalSTSClient);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.STSUniversalUser);
importClass(Packages.com.tivoli.am.fim.base64.BASE64Utility);

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
	var ivcredsXML = IDMappingExtUtils.stringToXMLElement(
			"<wss:BinarySecurityToken wsu:Id=\"uuid99785f92-0124-1282-a937-cf52545c78b4\""
			+ " xmlns:itam=\"urn:ibm:names:ITFIM:5.1:accessmanager\""
			+ " xmlns:wss=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\""
			+ " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\""
			+ " EncodingType=\"http://ibm.com/2004/01/itfim/base64encode\""
			+ " ValueType=\"http://ibm.com/2004/01/itfim/ivcred\">"
			+ ivcreds
			+ "</wss:BinarySecurityToken>");
	
	// exchange for STSUU		
	var res = LocalSTSClient.doRequest(
			"http://schemas.xmlsoap.org/ws/2005/02/trust/Validate", 
			"http://appliesto/stsuu",
			"http://issuer/ivcred", 
			ivcredsXML, 
			null);
	
	if (res.errorMessage == null) {
		var stsuu = new STSUniversalUser();
		stsuu.fromXML(res.token);
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
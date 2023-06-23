importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("FIDOInfomapConfig");

//
// Shared utility functions
//

function debugLog(s) {
    IDMappingExtUtils.traceString(s);
}

function jsToJavaArray(jsArray) {
    var javaArray = java.lang.reflect.Array.newInstance(java.lang.String, jsArray.length);
    for (var i = 0; i < jsArray.length; i++) {
            javaArray[i] = jsArray[i];
    }
    return javaArray;
}

function getInfomapUsername() {
	// get username from already authenticated user
	let result = context.get(Scope.REQUEST,
			"urn:ibm:security:asf:request:token:attribute", "username");
	debugLog("username from existing token: " + result);

	// if not there, try getting from session (e.g. UsernamePassword module)
	if (result == null) {
		result = context.get(Scope.SESSION,
				"urn:ibm:security:asf:response:token:attributes", "username");
		debugLog("username from session: " + result);
	}
	if (result != null) {
		// make it a javascript string - this prevents stringify issues later
		result = '' + result;
	}
	return result;
}

function sendJSONResponse(jObj) {
    page.setValue("/authsvc/authenticator/fido_infomap/jsonresponse.html");
    macros.put("@AUTHSVC_JSON_RESPONSE@", JSON.stringify(jObj));
    responseProcessed = true;
}

function sendErrorResponse(str) {
    page.setValue("/authsvc/authenticator/fido_infomap/error.html");
    macros.put("@ERROR_MSG@", str);
    responseProcessed = true;
}

// used by both the registration and login infomaps
var responseProcessed = false;
var lfc = fido2ClientManager.getClient(RPID);

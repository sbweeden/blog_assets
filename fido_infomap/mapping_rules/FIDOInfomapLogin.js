importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("FIDOInfomapConfig");

function debugLog(s) {
    IDMappingExtUtils.traceString(s);
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

function jsToJavaArray(jsArray) {
    var javaArray = java.lang.reflect.Array.newInstance(java.lang.String, jsArray.length);
    for (var i = 0; i < jsArray.length; i++) {
            javaArray[i] = jsArray[i];
    }
    return javaArray;
}

/*
 * Main body starts here
 */
var result = false;
var lfc = fido2ClientManager.getClient(RPID);
var responseProcessed = false;
   
// figure out what we are doing for this invocation
var action = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "action");

// perform any specific action first
if (action != null) {
    if (action.equals("getAssertionOptions")) {
        // get options and return as JSON
        let assertionOptionsStr = lfc.assertionOptions(JSON.stringify({
            userVerification: "required"
        }));
        debugLog("assertionOptionsStr: " + assertionOptionsStr);
        sendJSONResponse(JSON.parse(''+assertionOptionsStr));
    } else if (action.equals("processAssertionResponse")) {
        var assertionResponseStr = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "assertionResponse");
        if (assertionResponseStr != null) {
            let assertonResultStr = lfc.assertionResult(assertionResponseStr);
            debugLog("assertonResultStr: " + assertonResultStr);
            let assertionResult = JSON.parse(''+assertonResultStr);
            if (assertionResult.status == "ok") {
                // login as the user, including supplying any credentialData populated by the mediator as extended attributes
                context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", assertionResult.user.name);
    
                if (assertionResult.attributes != null && assertionResult.attributes.credentialData != null) {
                    Object.keys(assertionResult.attributes.credentialData).forEach((k) => {
                        if (assertionResult.attributes.credentialData[k] != null) {
                            if (Array.isArray(assertionResult.attributes.credentialData[k])) {
                                context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", k, jsToJavaArray(assertionResult.attributes.credentialData[k]));
                            } else {
                                context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", k, assertionResult.attributes.credentialData[k]);
                            }
                        }
                    });
                }
                result = true;
                responseProcessed = true;
            }
            
        } else {
            debugLog("processAssertionResponse action did not contain assertionResponse");
        }
    }
} 

// default action is to show the login page
if (!responseProcessed) {
    // note that we request a longer timeout (24 hours) here for options to be used for
    // autofill because the login page might be idle for ages. Our client uses seconds
    // but the response will be in milliseconds.
    let assertionOptionsStr = lfc.assertionOptions(JSON.stringify({
        userVerification: "required",
        timeout: 86400
    }));
    macros.put("@AUTOFILL_ASSERTION_OPTIONS_JSON@", assertionOptionsStr);
    page.setValue("/authsvc/authenticator/fido_infomap/login.html");
}


// final result - will be true if logging in
success.setValue(result);
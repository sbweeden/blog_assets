importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("FIDOInfomapUtils");

/*
 * Main body starts here
 */
var result = false;
var loginErrorStr = null;
   
// figure out what we are doing for this invocation
var action = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "action");

// perform any specific action first
if (action != null) {
    if (action.equals("getAssertionOptions")) {
        // get options and return as JSON
        // modal timeout is 2 minutes
        let assertionOptionsStr = lfc.assertionOptions(JSON.stringify({
            userVerification: "required",
            timeout: (2*60)
        }));
        debugLog("assertionOptionsStr: " + assertionOptionsStr);
        sendJSONResponse(JSON.parse(''+assertionOptionsStr));
    } else if (action.equals("getAssertionOptionsAutofill")) {
        // get options and return as JSON
        // autofill timeout is 30 minutes - this is used to set challenge refresh interval at browser
        let assertionOptionsStr = lfc.assertionOptions(JSON.stringify({
            userVerification: "required",
            timeout: (30*60)
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
            } else {
                loginErrorStr = JSON.stringify(assertionResult);
            }
            
        } else {
            debugLog("processAssertionResponse action did not contain assertionResponse");
        }
    }
} 

// default action is to show the login page
if (!responseProcessed) {
    //
    // note that we request a longer timeout (30 minutes) here for options to be used for
    // autofill because the login page might be idle for ages. The page will occassionally
    // refresh the challenge anyway, but this interrupts any in-progress attempt by the 
    // user to login, so we do not want to do that very often. 
    //
    // Our client uses seconds but the response will be in milliseconds as that is what 
    // WebAuthn uses. This ability to specify a custom timeout was added is ISVA 10.0.6.0.
    //
    let assertionOptionsStr = lfc.assertionOptions(JSON.stringify({
        userVerification: "required",
        timeout: (30*60)
    }));

    let loginJSON = {
        username: getInfomapUsername(),
        autofillAssertionOptions: JSON.parse(''+assertionOptionsStr)
    };
    if (loginErrorStr != null) {
        loginJSON.lastError = loginErrorStr;
    }
    macros.put("@ESCAPED_FIDO_LOGIN_JSON@", JSON.stringify(loginJSON));
    page.setValue("/authsvc/authenticator/fido_infomap/login.html");
}


// final result - will be true if logging in
success.setValue(result);
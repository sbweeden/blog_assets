importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importPackage(Packages.com.ibm.security.access.httpclient);
importMappingRule("KJUR");


// *********************************************************
// This is the Duo configuration required for this mechanism
//
// Note that the duo* variables should come from a "Web SDK" application configuration in Duo.
// The pointOfContact should be what the browser uses to contact your ISVA system, including the junction to AAC.
//
// For more information see: https://duo.com/docs/oauthapi#first-steps
// *********************************************************

let duoWebSDKClientId = "YOUR_VALUE";
let duoWebSDKClientSecret = "YOUR_VALUE";
let duoAPIEndpoint = "api-XXXXXXXX.duosecurity.com";
let pointOfContact = "https://your_webseal_hostname/mga";

// ***********************************
// These are general utility functions
// ***********************************

function debugLog(str) {
    if (typeof (console) != "undefined") {
            console.log(str);
    } else {
            IDMappingExtUtils.traceString(str);
    }
}

function generateRandom(len) {
    // generates a random string of digits - you can change the character set if you wish
    var chars = "0123456789abcdefghijklmnopqrstuvwxyz";
    var result = "";
    for (var i = 0; i < len; i++) {
            result = result + chars.charAt(Math.floor(Math.random()*chars.length));
    }
    return result;
}

/**
 * Utility to get the user display name from the the Infomap context
 */
function getInfomapUsername() {
    // get username from already authenticated user
    var result = context.get(Scope.REQUEST,
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

function getHttpClient() {
    return new HttpClientV2();
}

function traceHTTPResponse(methodName, httpResponse) {
	if (httpResponse == null) {
		debugLog(methodName + ": httpResponse object is null");			
	} else {
		debugLog(methodName + ": httpResponse response code: " + httpResponse.getCode() + " body: " + httpResponse.getBody());
	}
}

// *************************************************************************
// These are functions specifically for the Duo Universal Prompt Integration
// *************************************************************************


function buildClientAssertionJWT(aud) {
    // 5 mins
    let expires = Math.round((new Date()).getTime() / 1000) + 300;

    let alg = "HS256";

    let jwtClaims = {
        iss: duoWebSDKClientId,
        sub: duoWebSDKClientId,
        aud: aud,
        exp: expires,
        jti: generateRandom(64)
    };

    let jwtHeader = { 
        alg: alg,
        typ: "JWT"
    };

    return KJUR.jws.JWS.sign(alg, JSON.stringify(jwtHeader), JSON.stringify(jwtClaims), duoWebSDKClientSecret);
}

function doTokenExchange(code, authsvcstate) {
    let methodName = "doTokenExchange";

    let httpClient = getHttpClient();

    let headers = new Headers();
    let tokenEndpoint = "https://" + duoAPIEndpoint + "/oauth/v1/token";

    let policyID = ''+context.get(Scope.SESSION, "urn:ibm:security:asf:policy", "policyID");
    // extract the short policy name to avoid hard-coding the redirect URI path
    let shortPolicyName = policyID.substring(policyID.lastIndexOf(':')+1);

    //
    // rebuild the redirectURI - note this has to follow exactly what was done
    // in the login.html server-side template page scripting when building the
    // redirect_uri that is included in the request JWT
    //
    let redirectURI = pointOfContact + "/sps/authsvc/policy/" + shortPolicyName +
    "?operation=verify" +
    "&authsvcstate=" + authsvcstate + 
    "&StateId=" + authsvcstate;

    let client_assertion = buildClientAssertionJWT(tokenEndpoint);

    let objParams = {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: redirectURI,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: client_assertion
    }

    let params = new Parameters();
    Object.keys(objParams).forEach((p) => {
        params.addParameter(p, objParams[p]);
    });

    let httpResponse = httpClient.httpPost(
        tokenEndpoint,
        headers,
        params,
        null,
        null,
        null,
        null,
        null
    );

    traceHTTPResponse(methodName, httpResponse);
    return httpResponse;
}

function validateTokenResponse(tokenResponseObj, u) {
    let result = null;
    if (tokenResponseObj["id_token"] != null) {
        let isValid = KJUR.jws.JWS.verifyJWT(
            tokenResponseObj.id_token, 
            duoWebSDKClientSecret, 
            {
                alg: [ "HS256", "HS512" ],
                iss: [ "https://" + duoAPIEndpoint + "/oauth/v1/token" ],
                sub: [ u ],
                aud: [ duoWebSDKClientId ]
            }
        );

        if (!isValid) {
            throw "id_token JWT validation failed";
        }

        result = KJUR.jws.JWS.readSafeJSONString(b64utoutf8(tokenResponseObj.id_token.split(".")[1]));
    } else {
        throw "id_token not found";
    }
    return result;
}

// ****************************************************************************
// ******************** MAIN PROCESSING STARTS HERE  **************************
// ****************************************************************************

debugLog("duoauthnUniversalPrompt start");
let result = false;
let loginJSON = {};
let authorizeURLTemplate = null;
let oidcState = null;

// this gets used throughout
let username = getInfomapUsername();


try {
    if (username != null) {
        loginJSON.username = username;
        debugLog("The username is: " + username);    

        // get code and state from request if they exist
        let aznCode = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "code");
        let requestState = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "state");
        let authsvcState = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "authsvcstate");

        // is this the response from Duo OIDC?
        if (aznCode != null && aznCode.length() > 0 
            && requestState != null && requestState.length() > 0
            && authsvcState != null && authsvcState.length() > 0) {
            // retrieve session state and compare
            let sessionState = IDMappingExtUtils.getSPSSessionData("oidcState");
            if (sessionState != null && sessionState.equals(requestState)) {
                let hr = doTokenExchange(''+aznCode, ''+authsvcState);
                let responseObj = null;
                if (hr != null && hr.getCode() == 200) {
                    responseObj = JSON.parse(''+hr.getBody());

                    // perform JWT validation - this will return via exception if any errors
                    let payloadObj = validateTokenResponse(responseObj, username);

                    // check Duo-specific claims
                    if (payloadObj.preferred_username != username) {
                        throw "Invalid preferred_username in id_token";
                    }

                    if (!(payloadObj["auth_result"] != null && payloadObj.auth_result.status == "allow")) {
                        throw "id_token did not indicate successful authentication";
                    }

                    // must have worked - so complete login
                    result = true;

                } else {
                    throw ("Invalid status code from Duo token endpoint. Status code: " + (hr == null ? "UNKOWN" : hr.getCode()));
                }
            
            } else {
                throw ("Invalid OIDC state");
            }
        } else {
            // redirect for authorization

            // generate a new state parameter and save in session - note that we do not rely on authsvc state for this
            // since we do not use the authsvc StateId parameter in the redirect URI. Instead this InfoMap operates
            // only based on the SPS session cookie state.
            oidcState = generateRandom(64);
            IDMappingExtUtils.setSPSSessionData("oidcState", oidcState);

            // this is the start of the authorize URL redirect however
            // it will be augmented with extra parameters (specifically the request JWT)
            // in server-side template page scripting in the login.html page because
            // in this InfoMap we do not yet have access to the next StateId value
            authorizeURLTemplate = "https://" + duoAPIEndpoint + "/oauth/v1/authorize?" + 
                "response_type=code" + 
                "&client_id=" + duoWebSDKClientId;
        }
    } else {
        loginJSON.username = "unauthenticated";
        throw "Not authenticated";
    }    
} catch (e) {
    loginJSON.errmsg = "Error: " + e;
}

// establish page to return with macros
if (authorizeURLTemplate != null) {
    macros.put("@AUTHORIZE_URL_TEMPLATE@", authorizeURLTemplate);
    macros.put("@OIDC_STATE@", oidcState);

    // we also share these with the server-side template page scripting
    // so that config only lives in one place. They are needed to build
    // the request JWT
    macros.put("@USERNAME@", username);
    macros.put("@duoWebSDKClientId@", duoWebSDKClientId);
    macros.put("@duoWebSDKClientSecret@", duoWebSDKClientSecret);
    macros.put("@duoAPIEndpoint@", duoAPIEndpoint);
    macros.put("@pointOfContact@", pointOfContact);    
}
macros.put("@ESCAPED_LOGIN_JSON@", JSON.stringify(loginJSON));
page.setValue("/authsvc/authenticator/duo_universal_prompt/login.html");

// all done
success.setValue(result);
debugLog("duoauthnUniversalPrompt end");

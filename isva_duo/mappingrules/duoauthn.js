importMappingRule("duoutils");
importPackage(Packages.com.ibm.security.access.httpclient);

// this gets used throughout
var username = getInfomapUsername();

// human-visible correlation id - only used when initiating a new authentication
var correlationID = generateRandom(4);

function getHttpClient() {
    return new HttpClientV2();
}


function doPreAuth() {
    let methodName = "doPreAuth";
    let requestVars = generatePreAuth(username);
    let httpClient = getHttpClient();

    let headers = new Headers();
    headers.addHeader("Date", requestVars.Date);
    headers.addHeader("Authorization", requestVars.Authorization);
    let params = new Parameters();
    Object.keys(requestVars.params).forEach((p) => {
        params.addParameter(p, requestVars.params[p]);
    });

    let httpResponse = httpClient.httpPost(
        requestVars.URL,
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

function doAuth() {
    let methodName = "doAuth";

    let pushinfo = "correlation=" + correlationID;
    let requestVars = generateAuth(username, pushinfo);
    let httpClient = getHttpClient();

    let headers = new Headers();
    headers.addHeader("Date", requestVars.Date);
    headers.addHeader("Authorization", requestVars.Authorization);
    let params = new Parameters();
    Object.keys(requestVars.params).forEach((p) => {
        params.addParameter(p, requestVars.params[p]);
    });

    let httpResponse = httpClient.httpPost(
        requestVars.URL,
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

function doAuthStatus(txnId) {
    let methodName = "doAuthStatus";
    let requestVars = generateAuthStatus(txnId);
    let httpClient = getHttpClient();

    let headers = new Headers();
    headers.addHeader("Date", requestVars.Date);
    headers.addHeader("Authorization", requestVars.Authorization);

    let httpResponse = httpClient.httpGet(
        requestVars.URL,
        headers,
        null,
        null,
        null,
        null,
        null
    );

    traceHTTPResponse(methodName, httpResponse);
    return httpResponse;
}

function hasDeviceWithAuto(preAuthResponseObj) {
    let result = false;
    if (preAuthResponseObj != null && preAuthResponseObj.response != null && preAuthResponseObj.response.devices != null && preAuthResponseObj.response.devices.length > 0) {
        for (let i = 0; i < preAuthResponseObj.response.devices.length && !result; i++) {
            let device = preAuthResponseObj.response.devices[i];
            result = (device != null && device.capabilities != null && device.capabilities.indexOf("auto") >= 0);
        }
    }
    return result;
}


// ****************************************************************************
// ******************** MAIN PROCESSING STARTS HERE  **************************
// ****************************************************************************

debugLog("duoauthn start");
let result = false;
let loginJSON = {};

try {
    if (username != null) {
        loginJSON.username = username;

        // get last known transaction status within this session
        let lastTxnStatus = context.get(Scope.SESSION, "urn:myns", "txnStatus");
        // turn into JS string with a value
        if (lastTxnStatus != null) {
            lastTxnStatus = ''+lastTxnStatus;
        } else {
            lastTxnStatus = "unknown";
        }
        loginJSON.lastTxnStatus = lastTxnStatus;

        // is this the browser request that occurs after approval to complete the login?
        let completeAuthn = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "completeAuthn");
        if (completeAuthn != null && completeAuthn.equalsIgnoreCase("true") && lastTxnStatus == "allow") {
            // we have completed authentication successfully 
            result = true;
        } else {
            // is this a poll/refresh of current authentication status?
            let pollTxnId = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "txnId");
            if (pollTxnId != null) {
                // presume we are going to send this back again
                loginJSON.txnId = ''+pollTxnId;

                // perform a poll to check for status
                let hr = doAuthStatus(loginJSON.txnId);

                // when you poll with the Duo API and the transaction was already
                // waiting, and then you poll again, the request becomes a "long-poll"
                // and times out, resulting in hr above being null. So if we see that
                // build a fake response so we can continue processing
                let authStatusResponseObj = null;
                if (hr == null && lastTxnStatus == "waiting") {
                    debugLog("Building a fake response because still waiting");
                    authStatusResponseObj = {
                        response: {
                            result: "waiting"
                        },
                        stat: "OK"
                    };
                } else {
                    authStatusResponseObj = checkDuoStatOK(hr);
                }

                if (authStatusResponseObj.response.result == "allow") {
                    // authentication completed
                    context.set(Scope.SESSION, "urn:myns", "txnStatus", "allow");
                    loginJSON.lastTxnStatus = "allow";
                    // do not set result here - the browser will come back with a normal form post to complete login
                } else if (authStatusResponseObj.response.result == "waiting") {
                    // that is ok - do nothing and we'll send a JSON response
                    // we also record the fact that the txn is waiting so that 
                    // if the next poll happens before the user approves/denies and 
                    // it times out at the Duo server, we'll just assume its still
                    // waiting
                    context.set(Scope.SESSION, "urn:myns", "txnStatus", "waiting");
                    loginJSON.lastTxnStatus = "waiting";
                } else if (authStatusResponseObj.response.result == "deny") {
                    context.set(Scope.SESSION, "urn:myns", "txnStatus", "deny");
                    loginJSON.lastTxnStatus = "deny";
                    throw ("Request denied");
                } else {
                    throw ("Unrecognised Duo result during authStatus: " + authStatusResponseObj.response.result);
                }

                debugLog("authStatusResponseObj: " + JSON.stringify(authStatusResponseObj));
        
            } else {
                // otherwise lets kickoff duo login
        
                // first lets to a pre-auth to make sure the user is in Duo and has a device with auto mode
                let hr = doPreAuth();
                let preAuthResponseObj = checkDuoStatOK(hr);
                if (preAuthResponseObj.response.result == "auth") {
                    // if the user has at least one device with auto mode, proceed with that
                    if (hasDeviceWithAuto(preAuthResponseObj)) {
                        // kick off "auto" mode, which uses first device and best mech                        
                        hr = doAuth();
                        let authResponseObj = checkDuoStatOK(hr);

                        // something to diplay to the user on the browser for correlation with the push
                        loginJSON.correlationID = correlationID;
                        
                        // this will be returned in page for polling the result
                        loginJSON.txnId = authResponseObj.response.txid;

                        // for now set the status to unknown - the first poll should change this
                        context.set(Scope.SESSION, "urn:myns", "txnStatus", "unknown");
                    } else {
                        throw ("User is registered, but only auto mode is currently supported.");
                    }
                } else if (preAuthResponseObj.response.result == "enroll") {
                    throw ("Duo enrollment required: " + preAuthResponseObj.response.enroll_portal_url);
                } else {
                    throw ("Unrecognised Duo result during preAuth: " + preAuthResponseObj.response.result);
                }    
            }
        }
    } else {
        loginJSON.username = "unauthenticated";
        throw "Not authenticated";
    }
    
    debugLog("The username is: " + username);    
} catch (e) {
    loginJSON.errmsg = "Error: " + e;
}

// establish page to return with macros
macros.put("@ESCAPED_LOGIN_JSON@", JSON.stringify(loginJSON));
page.setValue("/authsvc/authenticator/duo/login.html");

// all done
success.setValue(result);
debugLog("duoauthn end");

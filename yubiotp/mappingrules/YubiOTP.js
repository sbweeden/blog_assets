//
// This infomap validates a Yubico OTP against the online validation service.
//
// It requires that a user has already performed first-factor authentication.
//
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importPackage(Packages.com.ibm.security.access.httpclient);
importMappingRule("KJUR");

//
// For details on obtaining an API_CLIENT_ID and API_SECRET_KEY see:
// https://upgrade.yubico.com/getapikey/
//
var API_CLIENT_ID="YOUR_VALUE";
var API_SECRET_KEY="YOUR_VALUE";

function debugLog(str) {
	if (typeof (console) != "undefined") {
		console.log(str);
	} else {
		IDMappingExtUtils.traceString(str);
	}
}

function arrayToLogStr(a) {
	var result = null;
	if (a != null) {
		var result = '[';
		for (var i = 0; i < a.length; i++) {
			result += a[i];
			if (i < (a.length-1)) {
				result += ',';
			}
		}
		result += ']';
	}
	return result;
}

// Used for debugging
function dumpContext() {
	debugLog("request attributes: " +context.get(Scope.REQUEST, "urn:ibm:security:asf:request", "attributes"));
	debugLog("request headers: " +context.get(Scope.REQUEST, "urn:ibm:security:asf:request", "headers"));
	
	let cookieValues = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:headers", "cookie");
	debugLog("cookie headers: " + arrayToLogStr(cookieValues));

	let parameters = context.get(Scope.REQUEST, "urn:ibm:security:asf:request", "parameters");
	debugLog("request parameters: " +parameters);
	if (parameters != null) {
		for (let i = parameters.iterator(); i.hasNext();) {
			let paramName = i.next();
			let paramValues = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameters", paramName);
			debugLog("paramName: " + paramName + " paramValues: " + arrayToLogStr(paramValues));
		}
	}

	//debugLog("response attrs: " +context.get(Scope.SESSION, "urn:ibm:security:asf:response", "attributes"));
}

function generateRandom(len) {
    // generates a random string of alpha-numerics
    let chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let result = "";
    for (let i = 0; i < len; i++) {
            result = result + chars.charAt(Math.floor(Math.random()*chars.length));
    }
    return result;
}

/**
 * Utility to get the user display name from the the Infomap context
 */
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

// Utility to determine if we are in authenticate or register mode
function getInfomapMode() {
	let error = {"errorMessage": "Invalid mode"};
	
	// see if we have something in this request
	let mode = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "mode");
	if (mode != null) {
		// validate it
		if (!(mode.equals("authenticate") || mode.equals("register"))) {
			debugLog("Invalid mode: " + mode);
			throw error;
		}

		// put in session
		context.set(Scope.SESSION, "urn:myns", "mode", mode);
		
	} else {
		// fallback to see if there is a mode in session
		mode = context.get(Scope.SESSION, "urn:myns", "mode");
	}
	debugLog("getInfomapMode: " + mode);	
	return mode;
}

function processSuccess() {
	success.setValue(true);
}

function processRegistered(username, publicID) {
	page.setValue("/authsvc/authenticator/yubiotp/registered.html");
	macros.put("@USERNAME@", username);
	macros.put("@PUBLICID@", publicID);
	success.setValue(false);
}

function processErrorResponse(e) {
	debugLog("processErrorResponse: " + JSON.stringify(e));
	page.setValue("/authsvc/authenticator/yubiotp/yubierror.html");
	macros.put("@ERROR_MESSAGE@", e.errorMessage);
	success.setValue(false);
}

function validateYubiOTPFormat(otp) {
	let result = {
		"publicID": "",
		"dynamicOTP": ""
	};
	
	let error = {"errorMessage": "Invalid OTP format"};
	
	if (otp == null || otp.length != 44 || otp.match(/^[a-z]+$/) == null) {
		throw error;
	}
	
	result.publicID = otp.substring(0,12);
	result.dynamicOTP = otp.substring(12);
	
	return result;
}

//
// Registers the YubiOTP publicID against a particular user. 
//
// This demonstration implementation uses the alias service to store
// the publicID of a registered key. You can replace this with alternative
// storage if you wish.
//
function registerKeyToUser(username, publicID) {

	let fedContextID = "YubiOTP";
	
	let found = false;
	let attrVals = IDMappingExtUtils.lookupAliasesForUserAsStringArray(fedContextID, username, IDMappingExtUtils.ALIAS_TYPE_SELF);
	if (attrVals != null) {
		for (let i = 0; i < attrVals.length && !found; i++) {
			if (attrVals[i].equals(publicID)) {
				found = true;
			}
		}			
	}

	if (!found) {
		IDMappingExtUtils.addAliasForUser(fedContextID, username, publicID, IDMappingExtUtils.ALIAS_TYPE_SELF);
		debugLog("Yubikey with OTP publicID: " + publicID + " is now registered to: " + username);
	}
}

//
// Validates that the YubiOTP with the given publicID is 
// registered to the user with the given username, throwing an error if not.
//
// This demonstration implementation uses the alias service to store
// the publicID of a registered key. You can replace this with alternative
// storage if you wish.
//
function validateKeyRegisteredToUser(username, publicID) {

	let fedContextID = "YubiOTP";
	let error = {"errorMessage": "Yubikey with publicID: " + publicID + " not registered to user: " + username};
	
	let found = false;
	let attrVals = IDMappingExtUtils.lookupAliasesForUserAsStringArray(fedContextID, username, IDMappingExtUtils.ALIAS_TYPE_SELF);
	if (attrVals != null) {
		for (let i = 0; i < attrVals.length && !found; i++) {
			if (attrVals[i].equals(publicID)) {
				found = true;
			}
		}			
	} else {
		throw error;
	}

	if (!found) {
		throw error;
	}
	// exit silently means it was found
	debugLog("Yubikey with OTP publicID: " + publicID + " is registered to: " + username);
}

//
// Calculate signature per: 
//     https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html
//
function generateYubicoSignature(params) {
	let jsKeys = Object.keys(params);
	jsKeys.sort();
	let sigBase = "";
	jsKeys.forEach((k) => {
		if (k != "h") {
			sigBase += k;
			sigBase += "=";
			sigBase += params[k];
			sigBase += "&";
		}
	});
	// remove trailing &
	sigBase = sigBase.substring(0, sigBase.length-1);
	debugLog("generateYubicoSignature sigBase: " + sigBase);

	let mac = new KJUR.crypto.Mac({alg: "HmacSHA1", "pass": {"b64":  API_SECRET_KEY}});
	mac.updateString(sigBase);
	let result = hextob64(mac.doFinal());
	debugLog("generateYubicoSignature sig: " + result); 
	return result;
}

//
// rsp is Java string
//
function parseYubicoResponse(rsp) {
	let error = {"errorMessage": "Invalid response from Yubicloud"};
	let result = {};
	
	// first split into lines of k=v pairs
	let strs = rsp.split("\n");
	if (strs != null && strs.length > 0) {
		for (let i = 0; i < strs.length; i++) {
			let kv = strs[i].split("=", 2);
			if (kv != null && kv.length == 2) {
				// each key should appear only once
				if (result[''+kv[0]] != null) {
					error.errorMessage = "Duplicate key in response: " + kv[0];
					throw error;
				}
				result[''+kv[0]] = ''+kv[1].trim();
			}
		}
	}
	
	// check that a correct signature is included
	if (!result["h"]) {
		error.errorMessage = "Signature not present in response";
		throw error;
	}
	
	// verify the signature in the response is correct
	if (result["h"] != generateYubicoSignature(result)) {
		error.errorMessage = "Invalid signature in response";
		throw error;		
	}
	
	return result;
}

//
// Calls the YubiCloud service to validate the OTP value.
// See: https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html
//
function validateYubiOTPValue(otp) {
	let error = {"errorMessage": "Unable to validate OTP"};
	let endpoint = "https://api.yubico.com/wsapi/2.0/verify";
	let httpsTrustStore = "rt_profile_keys";
	let nonce = generateRandom(20);
	
	let result = {};
	
	let qsParams = {
		"id": API_CLIENT_ID,
		"nonce": nonce,
		"otp": otp,
		"timestamp": "1"
	};
	// add signature
	qsParams["h"] = generateYubicoSignature(qsParams);
		
	let urlstr = endpoint + "?";
	let paramNames = Object.keys(qsParams);
	for (let i = 0; i < paramNames.length; i++) {
		urlstr += paramNames[i] + "=" + encodeURIComponent(qsParams[paramNames[i]]);
		if (i < (paramNames.length-1)) {
			urlstr += "&";
		}
	}
	debugLog("validateYubiOTPValue urlstr: " + urlstr);

	var hr = HttpClient.httpGet(urlstr, null, httpsTrustStore, null, null, null, null);
	if (hr != null) {
		var code = hr.getCode(); // this is int
		var rspBody = hr.getBody(); // this is java.lang.String

		debugLog("validateYubiOTPValue.code: " + code);
		debugLog("validateYubiOTPValue.body: " + rspBody);
		
		if (code == 200) {
			result = parseYubicoResponse(rspBody);
			if (result.status != "OK") {
				error.errorMessage = "Yubicloud API returned error: " + result.status;
				throw error;
			}
			
			if (otp != result.otp) {
				error.errorMessage = "Yubicloud API returned otp: " + result.otp + " that was different from original: " + otp;
				throw error;
			}
			
			if (nonce != result.nonce) {
				error.errorMessage = "Yubicloud API returned nonce: " + result.nonce + " that was different from original: " + nonce;
				throw error;
			}
			
			return result;			
		} else {
			error.errorMessage = "Invalid HTTP response code: " + code;
			throw error;
		}
	} else {
		debugLog("hr was null");
		throw error;
	}	
}


//////////// MAIN BODY STARTS HERE

debugLog("infomap_YubiOTP has been called");
dumpContext();

try {
	// error template
	let error = {"errorMessage": "Unknown error"};
	
	// get authenticate/register mode
	let mode = getInfomapMode();
	
	// check if we already have an authenticated user
	let existingUser = getInfomapUsername();
	
	// this is a register, or 2nd-factor example, so error out if no existig user
	if (existingUser == null) {
		error.errorMessage = "Not authenticated";
		throw error;
	}

	
	// check if we received an OTP
	let otp = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "otp");

	debugLog("mode: " + mode + " otp: " + otp);
	if (mode != null && otp != null) {
		// get OTP details - throws error if invalid OTP format
		let otpDetails = validateYubiOTPFormat(''+otp);
		
		// are we registering, or authenticating?
		if (mode.equals("authenticate")) {
			// check that the yubikey that generated the OTP is registered to the user
			validateKeyRegisteredToUser(existingUser, otpDetails.publicID);
			
			// validate that the YubiOTP value is valid
			let ykResult = validateYubiOTPValue(otp);
			
			// if you wanted to, the ykResult data could be added to the credential
			// or futher validation of things like timestamp or sessioncounter could be
			// performed
			
			// if we get here, it must have been valid
			processSuccess();
		} else {
			// registering
			let ykResult = validateYubiOTPValue(otp);
			
			registerKeyToUser(existingUser, otpDetails.publicID);
			
			// if we get here, registration successful
			processRegistered(existingUser, otpDetails.publicID);
		}
	} else {
		// send back the login/register page instead
		macros.put("@USERNAME@", existingUser);
		page.setValue("/authsvc/authenticator/yubiotp/yubiotp.html");
		success.setValue(false);
	}
	
} catch(e) {
	processErrorResponse(e);
}

debugLog("infomap_YubiOTP finished");

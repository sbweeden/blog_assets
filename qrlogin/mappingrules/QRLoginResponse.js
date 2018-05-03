importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

/*
 * This rule is to be used within an InfoMap authentication mechanism to
 * verify a qr login session. This is typically done via IBM Verify, although
 * there is a way below (set enableBrowserLSIEntryForTesting=true) to simulate
 * this with a different authenticated browser session.
 */

/*
 * this flag controls whether or not the HTML testing interface (for simulating IBM Verify role)
 * is enabled or not. If it's not, and the LSI is not available in the incoming authenticated request
 * then an error will be returned instead.
 */
var enableBrowserLSIEntryForTesting = false;

var STATE_LIFETIME_SECONDS = 120;
var cache = IDMappingExtUtils.getIDMappingExtCache();

// Get username from already authenticated user - this MUST be present
var username = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "username");
IDMappingExtUtils.traceString("username from existing token: " + username);
if (username != null) {
	// determine LSI from request
	var lsi = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "lsi");
	if (lsi != null && lsi.length() > 0) {
		// determine if such a session exists, and if it does, update it with the username
		var stateStr = cache.get(lsi);

		if (stateStr != null && stateStr.length() > 0) {
			var state = JSON.parse(''+stateStr);
			state["username"] = ''+username;
			// update the dsi-indexed copy as this is what the device polls on
			cache.put(state["dsi"], JSON.stringify(state), STATE_LIFETIME_SECONDS);

			// remove the lsi-indexed copy because lsi is single use
			cache.getAndRemove(lsi);
			
			page.setValue("/authsvc/authenticator/qrlogin/qrresponse_reply.html");
			macros.put("@MSG@", "Login complete");
		} else {
			page.setValue("/authsvc/authenticator/qrlogin/error.html");
			macros.put("@ERROR@", "No such session");			
		}		
	} else {
		if (enableBrowserLSIEntryForTesting) {
			// for browser testing - need to prompt for qr session
			macros.put("@USERNAME@", username);
			page.setValue("/authsvc/authenticator/qrlogin/qrresponse.html");
		} else {
			page.setValue("/authsvc/authenticator/qrlogin/error.html");
			macros.put("@ERROR@", "LSI missing from request");			
		}
	}
} else {
	page.setValue("/authsvc/authenticator/qrlogin/error.html");	
	macros.put("@ERROR@", "No username available on QR response");	
}

// this policy never does anything to the session
success.setValue(false);

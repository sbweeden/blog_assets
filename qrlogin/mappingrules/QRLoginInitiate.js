importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

IDMappingExtUtils.traceString("QRLoginInitiate called");

/*
 * This rule is to be used within an InfoMap authentication mechanism to
 * initiate login via scanning of a QR code. It will generate a random
 * session index - actually a pair of indexes called "lsi" (login session index)
 * and "dsi" (device session index). These are very similar in function to
 * the user_code and device_code found in the OAuth device flow specification.
 * 
 *  The indexes represent a pointer to a session state object, initially
 *  stored as an "unauthenticated" state in DMAP. The lsi is displayed as a QR 
 *  part of a QR Code to the end user. The browser (or programmatic client) to
 *  this initiate delegate polls using the dsi to check if the state of the
 *  session has been updated to authenticated (and by whom) such that when it 
 *  is updated this mechanism will then complete user authentication. 
 */
var STATE_LIFETIME_SECONDS = 120; // you get two minutes to scan the code! 
var result = false;
var cache = IDMappingExtUtils.getIDMappingExtCache();

function generateRandom(chars,len) {
    // generates a random string of alpha-numerics
    var result = "";
    for (var i = 0; i < len; i++) {
            result = result + chars.charAt(Math.floor(Math.random()*chars.length));
    }
    return result;
}

function generateLoginSessionIndex() {
	var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	return  generateRandom(chars,4) + "-" + generateRandom(chars,4); 
} 

function generateDeviceSessionIndex() {
	var chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	return  generateRandom(chars,50); 
} 

/*
 * First try getting the device session index from request
 * 
 * I know it's in the AAC session, but we are trying to demonstrate how the
 * client could actually be stateless from a browser-cookie perspective and use
 * the dsi as the state handle (again similar to OAuth device flow)
 * 
 */  
var dsi = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "dsi");

if (dsi != null && dsi != "") {
	// poll DMAP to retrieve current state
	var stateStr = cache.get(dsi);

	// does it exist?
	if (stateStr != null && stateStr.length() > 0) {
		var state = JSON.parse(''+stateStr);
		if (state["username"] != null) {
			/* 
			 * Check if this was just a poll, or the actual page load to complete the login.
			 * The polling flag is used to allow an ajax client in a browser to switch the 
			 * top-level window location before this mechanism performs user login.   
			 */
			var polling = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "polling");
			if (polling != null && polling.equalsIgnoreCase("true")) {
				// update the login ready state to true and return same page to client
				page.setValue("/authsvc/authenticator/qrlogin/qrlogin.html");
				macros.put("@LSI@", state["lsi"]);
				macros.put("@DSI@", dsi);
				macros.put("@LOGIN_READY@", "true");
			} else {
				// we are going to login - flush the entry from the cache
				cache.getAndRemove(dsi);
				
				// login as this user
				context.set(Scope.SESSION,
						"urn:ibm:security:asf:response:token:attributes", "username",
						state["username"]);
				
				// need this for test EPAC point of contact type
				context.set(Scope.SESSION,
						"urn:ibm:security:asf:response:token:attributes",
						"AUTHENTICATION_LEVEL", "1");

				// provide a prompt for the case where MMFA follows
				context.set(Scope.SESSION, "urn:ibm:security:asf:demo", "prompt",
						"Are you really trying to authenticate the login session: " + state["lsi"] + " as user: " + state["username"] + "?");

				result = true;
			}
		} else {
			// nothing to do - just return existing state to client so they can re-poll
			page.setValue("/authsvc/authenticator/qrlogin/qrlogin.html");
			macros.put("@LSI@", state["lsi"]);
			macros.put("@DSI@", dsi);
			macros.put("@LOGIN_READY@", "false");
		}
	} else {
		// timeout logging in
		page.setValue("/authsvc/authenticator/qrlogin/error.html");	
		macros.put("@ERROR@", "Login timeout");
	}
} else {
	// generate a new login session index, device session index, store state, display the page and continue
	lsi = generateLoginSessionIndex();
	dsi = generateDeviceSessionIndex();
	IDMappingExtUtils.traceString("generating new login session index: " + lsi + " and device session index: " + dsi);
	context.set(Scope.SESSION, "urn:ibm:security:asf:demo", "qr_login_session_index", lsi);
	context.set(Scope.SESSION, "urn:ibm:security:asf:demo", "qr_device_session_index", dsi);
	var state = {};
	state["lsi"] = lsi;
	state["dsi"] = dsi;
	cache.put(lsi, JSON.stringify(state), STATE_LIFETIME_SECONDS);
	cache.put(dsi, JSON.stringify(state), STATE_LIFETIME_SECONDS);
	page.setValue("/authsvc/authenticator/qrlogin/qrlogin.html");
	macros.put("@LSI@", lsi);
	macros.put("@DSI@", dsi);
	macros.put("@LOGIN_READY@", "false");
}

success.setValue(result);
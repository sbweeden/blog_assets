importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.ibm.security.access.user.UserLookupHelper);

/*
 * The purpose of this decision mapping rule is to determine if the user is going to attempt FIDO
 * authentication or fallback to regular Username/Password authentication.
 * 
 * It will first send down the detection page which will figure out if a remember-session JWT exists,
 * and if it does, call back to the assertion options endpoint to figure out if the user has any registered
 * FIDO credentials. 
 * 
 */

var RPID = "www.iamlab.ibm.com";
var optionalFIDOPage = "/authsvc/authenticator/optionalFIDO/optionalFIDO.html";

var result = false; 

/****************************** MAIN CODE STARTS HERE ******************************/

// the default is to send back the optionalFIDOPage
page.setValue(optionalFIDOPage);

// get possible expected request parameters
let usernameStr = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "username");
let passwordStr = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "password");
let fidoResponseStr = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "fidoResponse");

// is this U/P login?
if (usernameStr != null && passwordStr != null) {
	let authenticated = false;

	// this method of initialising UserLookupHelper will use the configuration
	// from the UsernamePassword mechanism, which should already be set
	let ulh = new UserLookupHelper();	
	ulh.init(true);

	// check username and password
	let user = ulh.getUser(usernameStr);
	if (user != null) {
		authenticated = user.authenticate(passwordStr);
	}

	if (authenticated) {
		// login from username/password succeeded
		IDMappingExtUtils.traceString("optionalFIDO do an actual login from valid password");
		context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", usernameStr);
		result = true;
	} else {
		// hmm could not authenticate the password. Set an error macro.
		IDMappingExtUtils.traceString("Password authentication failed for username: " + usernameStr);
		macros.put("@ERROR@", "Username/Password authentication failed");
	}


// is this a FIDO login?
} else if (fidoResponseStr != null) {
	// The user has performed a FIDO authentication ceremony. Let's try validate that.
	let fidoClient = fido2ClientManager.getClient(RPID);		
		let assertionResult = JSON.parse(fidoClient.assertionResult(fidoResponseStr));
		
		if (assertionResult.status == "ok") {
			// login with FIDO succeeded
			IDMappingExtUtils.traceString("optionalFIDO do an actual login from FIDO assertion result: " + JSON.stringify(assertionResult));
			context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", assertionResult.user.name);
			result = true;
		} else {
			// hmm assertion result was bad. Set an error macro.
			IDMappingExtUtils.traceString("FIDO authentication failed");
			macros.put("@ERROR@", "FIDO authentication failed");
		}
} else {
	// just fall through and send the optionalFIDO page
}

success.setValue(result);
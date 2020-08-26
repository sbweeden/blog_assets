importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.registrations.MechanismRegistrationHelper);

/*
 * The purpose of this decision mapping rule is to demonstrate branching AAC authentication policies.
 * 
 * It will first perform discovery to determine a list of 2FA mechanisms that the user has the necessary registration
 * or attributes such that they could use that mechanism for 2FA. For example we can detect if the user has registration for 
 * TOTP, IBM Verify, FIDO2, an email address attribute, or phone number, and only render only the list of possible 
 * options that this user could complete. 
 * 
 * Once the user chooses a particular method, we store any related necessary information in the authsvc context
 * (such as a delivery attribute like an email address or phone number) then direct the authentication service to the
 * corresponding policy branch. From there, the configured mechanisms in that branch take over and completes 2FA.
*/


var errorPage = "/authsvc/authenticator/select_2fa_branching/error.html";
var selectionPage = "/authsvc/authenticator/select_2fa_branching/selection.html";

var result = false; 

// Utility function to obscure a string, leaving head and tail chars intact and replaceing the rest with asterix, excluding any chars in excludeList
function obscureString(s,head,tail,excludeList) {
	let result = '';
	for (let i = 0; i < s.length; i++) {
		let c = s[i];
		if (i < head || (i+tail) >= s.length) {
			result = result + c;
		} else {
			result = result + ((excludeList.indexOf(c) < 0) ? '*' : c);
		}
	}
	return result;
}

/****************************** MAIN CODE STARTS HERE ******************************/

// You must be authenticated to use this mechanism since this is for 2FA and we perform user attribute lookup tasks
var username = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "username");
IDMappingExtUtils.traceString("username from existing token: " + username);
if (username != null) {
	// is this the result of the user selecting a method?
	let chosenMethodIndexStr = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "choice");
	if (chosenMethodIndexStr != null) {
		// retrieve the real session options and validate this is a permitted choice
		let sessionMethodsStr = context.get(Scope.SESSION, "urn:myns", "sessionMethods");
		if (sessionMethodsStr != null) {
			let sessionMethods = JSON.parse(''+sessionMethodsStr);
			let chosenMethodIndex = chosenMethodIndexStr - "0";
			if (chosenMethodIndex >= 0 && chosenMethodIndex < sessionMethods.length) {
				// this is ok, use the chosen method.
				
				// perform any pre-redirect session state establishment
				let methodType = sessionMethods[chosenMethodIndex]["type"];
				
				// email and sms otp use a delivery attribute
				if (methodType == "emailOTP" || methodType == "smsOTP") {
					//IDMappingExtUtils.setSPSSessionData("deliveryAttribute", sessionMethods[chosenMethodIndex]["deliveryAttribute"]);
					IDMappingExtUtils.traceString("Setting deliveryAttribute to: " + sessionMethods[chosenMethodIndex]["deliveryAttribute"]);
					context.set(Scope.SESSION, "urn:myns", "deliveryAttribute", sessionMethods[chosenMethodIndex]["deliveryAttribute"]);
				}
				
				// now set the branch
				IDMappingExtUtils.traceString("Setting branch to: " + sessionMethods[chosenMethodIndex]["branchName"]);
				state.put("decision", sessionMethods[chosenMethodIndex]["branchName"]);
				result = true;
			} else {
				// invalid index
				macros.put("@ERROR@", "Invalid request parameter: 'choice'.");
				page.setValue(errorPage);
			}
		} else {
			// error - we shouldn't be passed an choice index without there having been something put in the session 
			// first. This might be caused be loss of session state.
			macros.put("@ERROR@", "Required session state data not present.");
			page.setValue(errorPage);
		}
	} else {
		// figure out permitted methods and render the selection page 
		let permittedMethods = [];

		// get mechanims we know the user has access to
		let userMechanisms = {};
		let mechList = MechanismRegistrationHelper.getRegistrationsForUser(username);
		if (mechList != null) {
			let jsonMechList = JSON.parse(''+mechList.toString());
			//IDMappingExtUtils.traceString("jsonMechList: " + JSON.stringify(jsonMechList));
			jsonMechList.forEach((m) => {
				if (m["enabled"] || m["isEnrolled"]) {
					userMechanisms[m["mechanismURI"]] = true;
				}
			});
		}
		//IDMappingExtUtils.traceString("userMechanisms: " + JSON.stringify(userMechanisms));
		
		
		// can this user do email OTP (we look for a cred attribute, but you could use UserLookupHelper or SCIM to query as well)
		// this shows a hard-coded test value, and commented out is an example of looking for the value from a credential attribute
		// var emailAddress = "testuser@mailinator.com";
		var emailAddress = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "emailAddress");
		if (emailAddress != null) {
			// make JS string
			emailAddress = '' + emailAddress;
			// can use email
			var method = {};
			method["type"] = "emailOTP";
			method["branchName"] = "Email OTP";
			method["displayLabel"] = "Email OTP to: " + obscureString(emailAddress, 3, 5,['@']);
			method["deliveryAttribute"] = emailAddress;
			permittedMethods.push(method);
		}

		// can this user do SMS OTP (we look for a cred attribute, but you could use UserLookupHelper or SCIM to query as well)
		var phoneNumber = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "phoneNumber");
		if (phoneNumber != null) {
			// make JS string
			phoneNumber = '' + phoneNumber;
			// can use email
			var method = {};
			method["type"] = "smsOTP";
			method["branchName"] = "SMS OTP";
			method["displayLabel"] = "SMS OTP to: " + obscureString(phoneNumber,3,3,[]);
			method["deliveryAttribute"] = phoneNumber;
			permittedMethods.push(method);
		}
		
		// can this user do IBM Verify
		if (userMechanisms["urn:ibm:security:authentication:asf:mechanism:mmfa"]) {
			var method = {};
			method["type"] = "ibmVerify";
			method["branchName"] = "IBM Verify";
			method["displayLabel"] = "IBM Verify";
			permittedMethods.push(method);
		}
		
		// can this user do TOTP
		if (userMechanisms["urn:ibm:security:authentication:asf:mechanism:totp"]) {
			var method = {};
			method["type"] = "totp";
			method["branchName"] = "TOTP";
			method["displayLabel"] = "Time-based OTP";
			permittedMethods.push(method);			
		}
				
		// can this user do FIDO2
		if (userMechanisms["urn:ibm:security:authentication:asf:mechanism:fido2"]) {
			// can use FIDO2
			var method = {};
			method["type"] = "fido2";
			method["branchName"] = "FIDO2";
			method["displayLabel"] = "FIDO2";
			permittedMethods.push(method);
		}

		// add more methods here if you have them
		
		//IDMappingExtUtils.traceString("The final list of permitted methods is: " + JSON.stringify(permittedMethods));
		
		// if any possible methods, store them in session state, then send back just the ordered list of display labels to the selection page
		if (permittedMethods.length > 0) {
			context.set(Scope.SESSION, "urn:myns", "sessionMethods", JSON.stringify(permittedMethods));
			var displayLabels = [];
			for (var i = 0; i < permittedMethods.length; i++) {
				displayLabels.push(permittedMethods[i]["displayLabel"]);
			}
			macros.put("@LABELS@", JSON.stringify(displayLabels));
			page.setValue(selectionPage);			
		} else {
			// the user can't perform any 2FA because there are no registered 2fa mechanisms, and no attributes to do delivered OTP
			macros.put("@ERROR@", "2FA not possible for this user.");
			page.setValue(errorPage);
		}
	}
} else {
	// error - you must be authenticated.
	macros.put("@ERROR@", "You must be authenticated to use this mechanism");
	page.setValue(errorPage);
}

success.setValue(result);
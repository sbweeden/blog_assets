importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("MMFASCIMHelper");

/*
 * The purpose of this infomap is to demonstrate a simplistic way to "branch" AAC authentication policies.
 * 
 * It will first perform discovery to determine a list of 2FA mechanisms that the user has the necessary registration
 * or attributes such that they could use that mechanism for 2FA. For example we can detect if the user has registration for 
 * TOTP, IBM Verify, FIDO U2F, an email address attribute, or phone number, and only render only the list of possible 
 * options that this user could complete. 
 * 
 * Once the user chooses a particular method, we store any related necessary information in the SPS session
 * (such as a delivery attribute like an email address or phone number) then send back a page which redirects to the 
 * AAC policy that handles that particular method. From there, that method takes over and completes 2FA.
*/


var errorPage = "/authsvc/authenticator/select_2fa/error.html";
var selectionPage = "/authsvc/authenticator/select_2fa/selection.html";
var redirectPage = "/authsvc/authenticator/select_2fa/redirect.html";

// Utility function to obscure a string, leaving head and tail chars intact and replaceing the rest with asterix, excluding any chars in excludeList
function obscureString(s,head,tail,excludeList) {
	var result = '';
	for (var i = 0; i < s.length; i++) {
		var c = s[i];
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
	var chosenMethodIndexStr = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "choice");
	if (chosenMethodIndexStr != null) {
		// retrieve the real session options and validate this is a permitted choice
		var sessionMethodsStr = context.get(Scope.SESSION, "urn:myns", "sessionMethods");
		if (sessionMethodsStr != null) {
			var sessionMethods = JSON.parse(''+sessionMethodsStr);
			var chosenMethodIndex = chosenMethodIndexStr - "0";
			if (chosenMethodIndex >= 0 && chosenMethodIndex < sessionMethods.length) {
				// this is ok, use the chosen method.
				
				// perform any pre-redirect session state establishment
				var methodType = sessionMethods[chosenMethodIndex]["type"];
				
				// email and sms otp use a delivery attribute
				if (methodType == "emailOTP" || methodType == "smsOTP") {
					IDMappingExtUtils.setSPSSessionData("deliveryAttribute", sessionMethods[chosenMethodIndex]["deliveryAttribute"]);
				}
				
				// now do the redirect
				macros.put("@POLICYURI@", sessionMethods[chosenMethodIndex]["policyURI"]);
				page.setValue(redirectPage);
				
				
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
		var permittedMethods = [];
		
		
		// can this user do email OTP (we look for a cred attribute, but you could use UserLookupHelper or SCIM to query as well)
		// this shows a hard-coded test value, and commented out is an example of looking for the value from a credential attribute
		var emailAddress = "testuser@mailinator.com"; // context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "emailAddress");
		if (emailAddress != null) {
			// make JS string
			emailAddress = '' + emailAddress;
			// can use email
			var method = {};
			method["type"] = "emailOTP";
			method["policyURI"] = "urn:ibm:security:authentication:asf:emailOTP";
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
			method["policyURI"] = "urn:ibm:security:authentication:asf:smsOTP";			
			method["displayLabel"] = "SMS OTP to: " + obscureString(phoneNumber,3,3,[]);
			method["deliveryAttribute"] = phoneNumber;
			permittedMethods.push(method);
		}
		
		// can this user do IBM Verify
		if (isIBMVerifyRegisteredForUser(username)) {
			// can use IBM Verify
			var method = {};
			method["type"] = "ibmVerify";
			method["policyURI"] = "urn:ibm:security:authentication:asf:mmfa_initiate_simple_login";			
			method["displayLabel"] = "IBM Verify";
			permittedMethods.push(method);
		}
		
		// can this user do TOTP
		var canDoTOTP = (IDMappingExtUtils.retrieveSecretKey("otpfed","jdbc_userinfo",username,"otp.hmac.totp.secret.key","urn:ibm:security:otp:hmac") != null);
		if (canDoTOTP) {
			var method = {};
			method["type"] = "totp";
			method["policyURI"] = "urn:ibm:security:authentication:asf:custom_totp";			
			method["displayLabel"] = "Time-based OTP";
			permittedMethods.push(method);			
		}
		
		if (isFIDOU2FRegisteredForUser(username)) {
			// can use FIDO U2F
			var method = {};
			method["type"] = "fidou2f";
			method["policyURI"] = "urn:ibm:security:authentication:asf:u2f_authenticate";			
			method["displayLabel"] = "FIDO U2F";
			permittedMethods.push(method);
		}
		

		// add more methods here if you have them
		
		
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

// this infomap actually never logs you in
success.setValue(false);
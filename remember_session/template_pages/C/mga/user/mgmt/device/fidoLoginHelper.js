//
// Helper functions for FIDO login logic
// This page must be deployed in the mga/user/mgmt/device page template path
// as files that directory are able to have the FIDO2_RELYING_PARTIES macro populated.
//

// name of the localStorage index where we will store the remember-session 
// JWT and information on the username who last logged in
const LS_AMBIENT_CREDENTIALS = "ambientCredentials";
var ac = null;

function getAmbientCredentials() {
	let acStr = localStorage.getItem(LS_AMBIENT_CREDENTIALS);
	return (acStr == null ? {} : JSON.parse(acStr));
}

function storeAmbientCredentials() {
	localStorage.setItem(LS_AMBIENT_CREDENTIALS, JSON.stringify(ac));
}

function addHidden(theForm, key, value) {
	// Create a hidden input element, and append it to a form
	let input = document.createElement('input');
	input.type = 'hidden';
	input.name = key;
	input.value = value;
	theForm.appendChild(input);
}

function getBaseURL() {
	var locationHostPort = location.hostname+(location.port ? ':'+location.port: ''); 
	var baseURL = location.protocol+'//'+locationHostPort;

	return baseURL;
}

function htmlEncode(s) {
	if (s) {
		return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
	} else {
		return '';
	}
}

function htmlDecode(s) {
	if (s) {
		return s.replace(/&quot;/g, '"').replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&amp;/g, '&');
		
	} else {
		return '';
	}
}

function base64URLEncode(bytes, encoding = 'utf-8') {
    if(bytes == null || bytes.length == 0) {
        return null;
    }
    var str = base64js.fromByteArray(new Uint8Array(bytes));
    str = str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    return str;
}

function base64URLDecode(str, encoding = 'utf-8') {
    if(str == null || str == "") {
        return null;
    }

    var str = str.replace(/-/g, '+').replace(/_/g, '\/');

    var pad = str.length % 4;
    if(pad) {
      str += new Array(5-pad).join('=');
    }

    var bytes = base64js.toByteArray(str);
    return bytes.buffer;
}

function getRPID() {
	return location.hostname;
}

function getFIDO2RPBaseURL() {
	var baseURL = getBaseURL();

	var relyingParties = @FIDO2_RELYING_PARTIES@;
	var rpID = getRPID();
	
	var rpDefinitionID = relyingParties[rpID];
	if (rpDefinitionID == null) {
		rpDefinitionID = "UNDEFINED_RPID";
	}
	
	return (baseURL + '/mga/sps/fido2/' + rpDefinitionID);	
}

/**
* This function uses the remember-session data in a "whoami" HTTP header
* to make the assertion options call authenticated as a user. This allows
* discovery of registered credentials for the user.
*/
function getFIDOAssertionOptions(cb, cberr) {
	fetch (
		getFIDO2RPBaseURL() + "/assertion/options",
		{
			method: "POST",
			headers: {
				"Accept": "application/json",
				"whoami": ac.whoami
			},
			body: JSON.stringify({ username: ac.username, userVerification: "required"}),
			credentials: "omit"
		}
	).then((response) => {
		return response.json();
	}).then((data) => {
		// make sure this is not a login challenge response
		if (data.operation != null && data.operation == "login") {
			throw "whoami token is not valid";
		}
		// if we wanted to do specific filtering of allowCredentials, here is a good spot

		// now invoke the callback function with the assertion options data
		cb(data);
	}).catch((e) => {
		cberr(e);
	});
}

/**
* Massages b64url encoded fields into data types needed for WebAuthn, then invokes
* navigator.credentials.get. 
*/
function processAssertionOptionsResponse(options, cberr) {
	console.log("processAssertionOptionsResponse using options: " + JSON.stringify(options));
	
	// remove the status and errorMessage keys
	delete options["status"];
	delete options["errorMessage"];
	
	// continue to call navigator.credentials.get, start with a deep copy of the server options because we modify them
	let serverOptions = JSON.parse(JSON.stringify(options));

	// massage some of the b64u fields into the required ArrayBuffer types
	var b64uChallenge = serverOptions.challenge;
	serverOptions.challenge = base64URLDecode(b64uChallenge);

	if (serverOptions["allowCredentials"] != null && serverOptions["allowCredentials"].length > 0) {
		for (var i = 0; i < serverOptions["allowCredentials"].length; i++) {
			var b64uCID = serverOptions.allowCredentials[i].id;
			serverOptions.allowCredentials[i].id= new base64URLDecode(b64uCID);
		}
	}

	var credRequestOptions = { "publicKey": serverOptions };
	console.log("calling navigator.credentials.get with: " + JSON.stringify(credRequestOptions));
	
	// call the webauthn API
	navigator.credentials.get(credRequestOptions).then(
		function(authenticateResponse) {
			// success
			console.log("Received from authenticator: " + JSON.stringify(authenticateResponse));
			
			// marshall the important parts of the response into an object which we send to the server for validation
			let clientDataJSONB64u = base64URLEncode(authenticateResponse.response.clientDataJSON);
			let authenticatorDataCBORB64u = base64URLEncode(authenticateResponse.response.authenticatorData);
			let signatureB64u = base64URLEncode(authenticateResponse.response.signature);
			let userHandleB64U = base64URLEncode(authenticateResponse.response.userHandle);
			let clientExtensionResults = authenticateResponse.getClientExtensionResults();
			
			let assertionResponseObject = {};
			assertionResponseObject["id"] = authenticateResponse.id;
			assertionResponseObject["rawId"] = authenticateResponse.id;
			assertionResponseObject["type"] = "public-key";
			assertionResponseObject["response"] = {
					"clientDataJSON": clientDataJSONB64u,
					"authenticatorData": authenticatorDataCBORB64u,
					"signature": signatureB64u,
					"userHandle": userHandleB64U,
			};
			
			// if there are extensions results, include those
			if (clientExtensionResults != null) {
				assertionResponseObject["getClientExtensionResults"] = clientExtensionResults;
			}
			
			// send to server for result processing
			console.log("Sending to server: " + JSON.stringify(assertionResponseObject));

			/* 
			 * this is done as a FORM post back to the InfoMap
			 */
			let operationForm = document.getElementById("operationForm");
			addHidden(operationForm, "fidoResponse", JSON.stringify(assertionResponseObject));
			operationForm.submit();
		}, function(err) {
			// error
			console.log(err);
			cberr(err);
		}
	);
}

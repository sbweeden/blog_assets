// set of client-side helper functions for passkey login page

// assumes availability of fido_infomap_helper.js and its dependencies before this one
window.addEventListener("load", loginStartup);

var loginPageJSON = JSON.parse(htmlDecode(document.getElementById('fido_login_tags').textContent));

var autofillAssertionOptions = loginPageJSON.autofillAssertionOptions;
console.log("autofillAssertionOptions: " + JSON.stringify(autofillAssertionOptions));

// used for autofill UI
var abortController;
var abortSignal;
var autofillWebAuthnPromise = null;

function getLoginAPIAuthSvcURL() {
    return getBaseURL() + '/mga/sps/apiauthsvc/policy/fido_infomap_login';
}

//
// This function is only declared async because I was experimenting with calling
// await for the autofillWebAuthnPromise
//
async function modalLogin() {
    hideDiv('errorDiv');
    if (abortController) {
        // need to abort the autofill call. 
        console.log("Aborting the autofill webauthn call");
        abortController.abort("AbortError");

        // now we really *should* wait for the abort to complete
        // by calling:
        //
        // await autofillWebAuthnPromise;
        // 
        // however if you do this on Safari (at least at time of writing)
        // with Safari 16.5.1, then the browser will complain with
        // the warning:
        // User gesture is not detected. To use the WebAuthn API, call 'navigator.credentials.create' or 'navigator.credentials.get' within user activated events.
        //
        // and the user gets an ugly warning asking them to allow the modal call to WebAuthn (which they should not get)
        //
        // So instead we just completely assume that it's aborted
        // somewhat synchronously by the OS, and get on with calling
        // the modal UI. 
        //
        // if (autofillWebAuthnPromise) {
        //     await autofillWebAuthnPromise;
        //     autofillWebAuthnPromise = null;
        // }
    }

    kickoffModalLogin();
}

function kickoffModalLogin() {
    // get fresh assertion options
    $.ajax({
        type: "PUT",
        url: getLoginAPIAuthSvcURL(),
        data: JSON.stringify({
            action: "getAssertionOptions"
        }),
        contentType: "application/json; charset=utf-8",
        dataType: "json",
        beforeSend: function(xhr) {
            xhr.setRequestHeader("Accept: application/json");
        }
    }).done(function(data, textStatus, jqXHR) {
        if (jqXHR.status == 200) {
            processAssertionOptionsResponse(data, false);
        } else {
            errMsg = "Unexpected HTTP response code in kickoffModalLogin: " + jqXHR.status;
            showError(errMsg);
            console.log(errMsg);
        }

    }).fail(function(jqXHR, textStatus, errorThrown) {
        errMsg = "Unexpected HTTP response code in kickoffModalLogin: " + jqXHR.status;
        showError(errMsg);
        console.log(errMsg);
});    
}

function kickoffAutofill() {
    let serverOptions = JSON.parse(JSON.stringify(autofillAssertionOptions));

    processAssertionOptionsResponse(serverOptions, true);
}

function base64URLEncodeArrayBuffer(ab) {
    return hextob64u(BAtohex(new Uint8Array(ab)));
}

function processAssertionOptionsResponse(options, isAutofill) {
    console.log("Received assertion options: " + JSON.stringify(options));

    let serverOptions = JSON.parse(JSON.stringify(options));

	// remove the status and errorMessage keys
	delete serverOptions["status"];
	delete serverOptions["errorMessage"];

	// massage some of the b64u fields into the required ArrayBuffer types
	serverOptions.challenge = new Uint8Array(b64toBA(b64utob64(serverOptions.challenge)));

    if (serverOptions.allowCredentials) {
        for (let i = 0; i < serverOptions.allowCredentials.length; i++) {
            serverOptions.allowCredentials[i].id = new Uint8Array(b64toBA(b64utob64(serverOptions.allowCredentials[i].id)));
        }
    }

    let credGetOptions = { "publicKey": serverOptions };

    if (isAutofill) {
        // add extra options for autofill
        abortController = new AbortController();
        abortSignal = abortController.signal;
        credGetOptions.signal = abortSignal;
        credGetOptions.mediation = "conditional";
    }

	console.log("Calling navigator.credentials.get with options: " + JSON.stringify(credGetOptions));

	// call the webauthn API
	let webauthnPromise = navigator.credentials.get(credGetOptions).then(function (assertion) {

        // No longer require the abortController if autofill UI was taking place 
		abortController = null;

        // build the JSON assertion response that the server will validate
        let assertionResponseObject = {
            id: assertion.id,
            rawId: base64URLEncodeArrayBuffer(assertion.rawId),
            response: {
                clientDataJSON: base64URLEncodeArrayBuffer(assertion.response.clientDataJSON),
                authenticatorData: base64URLEncodeArrayBuffer(assertion.response.authenticatorData),
                signature: base64URLEncodeArrayBuffer(assertion.response.signature),
                userHandle: base64URLEncodeArrayBuffer(assertion.response.userHandle)
            },
            type: assertion.type,
            getClientExtensionResults: assertion.getClientExtensionResults(),
            authenticatorAttachment: (assertion.authenticatorAttachment || "")
        };

        processAssertionResponse(assertionResponseObject);
    }).catch(function (err) {

        // if this is the autofill call, then this might be perfectly normal since it may have been aborted
        // as a result of the user pressing the Login with a passkey button 
        if (abortSignal != null && abortSignal.aborted) {
            abortController = null;
            abortSignal = null;
            console.log("Conditional request aborted");            
        } else {
			let errMsg = "processAssertionOptionsResponse failed via catch: " + err;
            showError(errMsg);
            console.log(errMsg);
        }
    });

    if (isAutofill) {
        // store this, so on conforming browsers we can await it
        // before starting the modal UI
        autofillWebAuthnPromise = webauthnPromise;
    }
}

function processAssertionResponse(assertionResponseObject) {

    // this policy operates stateless, so strip StateId
    newAction = $('#loginForm').attr('action').replace(/\?StateId=.*$/, '');
    $('#loginForm').attr('action', newAction);
    // populate the assertion response, and submit the login form
    $('#assertionResponse').attr('value', JSON.stringify(assertionResponseObject));
    $('#loginForm').submit();
}

function loginStartup() {
    performWebAuthnFeatureDiscovery()
    .then((x) => {
        // render feature table
        renderFeatureTable();

        // set up a handler for the register button
        $('#passkeyLoginButton').click(() => { modalLogin(); });

        // if autofill is available, kick of the condiitonal mediation flow
        if (isAutofillAvailable) {
            showDiv('autofillDiv');
            kickoffAutofill();
        }

        // if there was an error on previous login attempt, show it
        if (loginPageJSON.lastError != null) {
            showError(loginPageJSON.lastError);
            console.log(loginPageJSON.lastError);
        }
    });
}
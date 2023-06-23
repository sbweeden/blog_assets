// set of client-side helper functions for passkey login page

// assumes availability of fido_infomap_helper.js and its dependencies before this one
window.addEventListener("load", loginStartup);

var login_dataSetValues = document.currentScript.dataset;
console.log("login_dataSetValues: " + JSON.stringify(login_dataSetValues));

var loginPageJSON = JSON.parse(document.getElementById('fido_login_tags').textContent);
var autofillAssertionOptions = loginPageJSON.autofillAssertionOptions;
console.log("autofillAssertionOptions: " + JSON.stringify(autofillAssertionOptions));

// used for autofill UI
var abortController;
var abortSignal;
var abortTimer;

function getLoginAPIAuthSvcURL() {
    return getBaseURL() + '/mga/sps/apiauthsvc/policy/fido_infomap_login';
}

function modalLogin() {
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
            console.log("Unexpected HTTP response code in kickoffModalLogin: " + jqXHR.status);
        }

    }).fail(function(jqXHR, textStatus, errorThrown) {
        console.log("Unexpected HTTP response code in kickoffModalLogin: " + jqXHR.status);
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
	navigator.credentials.get(credGetOptions).then(function (assertion) {

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
        console.log("Error calling navigator.credentials.get: " + err);
    });
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
    });
}
    // set of client-side helper functions for passkey login page

    // assumes availability of fido_infomap_helper.js and its dependencies before this one
    window.addEventListener("load", loginStartup);

    var loginPageJSON = JSON.parse(htmlDecode(document.getElementById('fido_login_tags').textContent));
    loginUsername = loginPageJSON.username;
    var autofillAssertionOptions = loginPageJSON.autofillAssertionOptions;
    console.log("autofillAssertionOptions: " + JSON.stringify(autofillAssertionOptions));

    // used for autofill UI
    var abortController = null;
    var abortSignal = null;
    var autofillWebAuthnPromise = null;
    var autofillRefreshTimer = null;

    function getLoginAPIAuthSvcURL() {
        return getBaseURL() + '/mga/sps/apiauthsvc/policy/fido_infomap_login';
    }


    function modalLogin() {
        hideDiv('errorDiv');

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
                errMsg = "Unexpected HTTP response code in modalLogin: " + jqXHR.status;
                showError(errMsg);
                console.log(errMsg);
            }

        }).fail(function(jqXHR, textStatus, errorThrown) {
            errMsg = "Unexpected HTTP response code in modalLogin: " + jqXHR.status;
            showError(errMsg);
            console.log(errMsg);
        });
    }

    function refreshAutofill() {

        // only do something if autofill is available
        if (isAutofillAvailable) {
            // called occassionally via a timer to get a fresh challenge
            // get fresh assertion options
            $.ajax({
                type: "PUT",
                url: getLoginAPIAuthSvcURL(),
                data: JSON.stringify({
                    // the only difference here is a longer timeout is returned
                    action: "getAssertionOptionsAutofill"
                }),
                contentType: "application/json; charset=utf-8",
                dataType: "json",
                beforeSend: function(xhr) {
                    xhr.setRequestHeader("Accept: application/json");
                }
            }).done(function(data, textStatus, jqXHR) {
                if (jqXHR.status == 200) {
                    // restart autofill with the new options - this will setup a new timer also
                    processAssertionOptionsResponse(data, true);
                } else {
                    errMsg = "Unexpected HTTP response code in refreshAutofill: " + jqXHR.status;
                    showError(errMsg);
                    console.log(errMsg);
                }
            }).fail(function(jqXHR, textStatus, errorThrown) {
                errMsg = "Unexpected HTTP response code in refreshAutofill: " + jqXHR.status;
                showError(errMsg);
                console.log(errMsg);
            });
        }
    }

    function cleanupAutofillControls() {
        abortController = null;
        abortSignal = null;
        // if there is an autofill refresh challenge timer active, stop it
        if (autofillRefreshTimer != null) {
            console.log("Canceling autofill refresh timer");
            window.clearTimeout(autofillRefreshTimer);
            autofillRefreshTimer = null;
        }
        autofillWebAuthnPromise = null;
    }

    async function abortAutofillIfRunning(shouldWait) {
        //
        // If autofill is active, abort it. 
        // Note use of the Error class - this is needed to get consistent
        // behaviour in the parameter passed to the catch() block of navigator.credentials.get
        //
        if (abortController != null) {
            console.log("Aborting existing autofill webauthn call");
            let abortError = new Error('Aborting existing autofill webauthn call');
            abortError.name = 'AbortError';
            abortController.abort(abortError);

            //
            // now we really *should* wait for the abort to complete in all cases when aborting
            // however if you do this on Safari (at least at time of writing
            // with Safari 16.5.1) when your are about to start a modal flow, 
            // then the browser will complain with the warning:
            //
            // User gesture is not detected. To use the WebAuthn API, call 'navigator.credentials.create' or 'navigator.credentials.get' within user activated events.
            //
            // and the user gets an ugly warning asking them to allow the modal call to WebAuthn (which they should not get)
            //
            // see: https://bugs.webkit.org/show_bug.cgi?id=258642
            //
            // So instead, in that case, we just completely assume that it's aborted
            // somewhat synchronously by the OS. This seems to work on Chrome and Safari.
            // 
            // When the bug is fixed, remove " && shouldWait" from condition below
            // and also the abortSignal.aborted would then be the only check necessary
            // in the catch block of the webauthn call below.
            //
            if (autofillWebAuthnPromise && shouldWait) {
                console.log("Waiting for existing autofill to abort");
                await autofillWebAuthnPromise;
                console.log("Finished waiting for existing autofill to abort");
                autofillWebAuthnPromise = null;
            }

            // regardless of whether we waited or not, clean up all the autofill control variables
            cleanupAutofillControls();
        }
    }

    function base64URLEncodeArrayBuffer(ab) {
        return hextob64u(BAtohex(new Uint8Array(ab)));
    }

    async function processAssertionOptionsResponse(options, isAutofill) {
        console.log("Received assertion options: " + JSON.stringify(options));

        // if there is an existing autofill in progress, abort it here
        // and wait for that to complete before proceeding
        await abortAutofillIfRunning(isAutofill);
        
        // prepare webauthn input
        let serverOptions = JSON.parse(JSON.stringify(options));

        // remove any status and errorMessage keys
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
            // add extra options for new autofill call
            abortController = new AbortController();
            abortSignal = abortController.signal;
            credGetOptions.signal = abortSignal;
            credGetOptions.mediation = "conditional";
        }

        console.log("Calling navigator.credentials.get with options: " + JSON.stringify(credGetOptions));

        // call the webauthn API
        let webauthnPromise = navigator.credentials.get(credGetOptions).then(function (assertion) {

            // on successful assertion we don't need any of these any more
            cleanupAutofillControls();

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
                getClientExtensionResults: assertion.getClientExtensionResults()
            };
            if (assertion.authenticatorAttachment !== undefined) {
                assertionResponseObject["authenticatorAttachment"] = assertion.authenticatorAttachment;
            }

            processAssertionResponse(assertionResponseObject);
        }).catch(function (err) {
            //
            // if this is the autofill call, then this might be perfectly normal since it may have been aborted
            // as a result of the user pressing the Login with a passkey button 
            // abortSignal might be null because we don't await the promise to finish in modal case due to Safari bug, 
            // so also check if the err is an Error with name "AbortError" as an alternative for checking if we have been aborted.
            //
            //console.log("catch block: err: " + err + " typeof(err): " + typeof(err) + " isAutofill: " + isAutofill + " abortSignal: " + abortSignal + " abortSignal.aborted: " + (abortSignal != null ? abortSignal.aborted : "null") + " err.name: " + ((err != null && err.name != null) ? err.name : "null") );

            if ((abortSignal != null && abortSignal.aborted) || (err != null && err.name != null && err.name == "AbortError")) {
                console.log("Autofill request aborted");
                cleanupAutofillControls();
            } else {
                let errMsg = "processAssertionOptionsResponse failed via catch: " + err;
                showError(errMsg);
                console.log(errMsg);
            }

            // if the modal was aborted, resume autofill if supported
            if (!isAutofill && isAutofillAvailable) {
                console.log("calling kickoffAutofill from within catch handler of modal webauthn");
                refreshAutofill();
            }
        });

        if (isAutofill) {
            // store this, so on conforming browsers we can await it
            // before starting the modal UI
            autofillWebAuthnPromise = webauthnPromise;

            // set a timer to get fresh options every now and then
            // use 30 seconds (which was the old ISVA default) or
            // 30 seconds less than the timeout if thats larger.
            let refreshInterval = 30000;
            if (options.timeout != null && options.timeout > 60000) {
                refreshInterval = options.timeout - 30000;
            }
            console.log("Will get a fresh autofill challenge in (ms): " + refreshInterval);
            autofillRefreshTimer = window.setTimeout(refreshAutofill, refreshInterval);
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

            // set up a handler for the passkey login button
            $('#passkeyLoginButton').click(() => { modalLogin(); });

            // if autofill is available, kick of the condiitonal mediation flow
            if (isAutofillAvailable) {
                showDiv('autofillDiv');
                processAssertionOptionsResponse(JSON.parse(JSON.stringify(autofillAssertionOptions)), true);
            }

            // if there was an error on previous login attempt, show it
            if (loginPageJSON.lastError != null) {
                showError(loginPageJSON.lastError);
                console.log(loginPageJSON.lastError);
            }
        });
    }
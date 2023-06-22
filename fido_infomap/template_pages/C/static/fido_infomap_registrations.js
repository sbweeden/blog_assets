// set of client-side helper functions for FIDO registrations page

// assumes availability of fido_infomap_helper.js and its dependencies before this one
window.addEventListener("load", registrationsStartup);

var registrations_dataSetValues = document.currentScript.dataset;
console.log("registrations_dataSetValues: " + JSON.stringify(registrations_dataSetValues));

var registrationsPageJSON = JSON.parse(document.getElementById('fido_registrations_tags').textContent);
var fidoRegistrations = registrationsPageJSON.fidoRegistrations;
console.log("fidoRegistrations: " + JSON.stringify(fidoRegistrations));

function getRegistrationsAPIAuthSvcURL() {
    return getBaseURL() + '/mga/sps/apiauthsvc/policy/fido_infomap_registrations';
}

function deleteRegistration(id) {
    console.log("Deleting registration with id: " + id);
    $.ajax({
        type: "PUT",
        url: getRegistrationsAPIAuthSvcURL(),
        data: JSON.stringify({
            action: "deleteRegistration",
            id: id
        }),
        contentType: "application/json; charset=utf-8",
        dataType: "json",
        beforeSend: function(xhr) {
            xhr.setRequestHeader("Accept: application/json");
        }

    }).done(function(data, textStatus, jqXHR) {
        if (jqXHR.status == 200) {
            console.log("data after delete: " + JSON.stringify(data));
            fidoRegistrations = data;
            renderRegistrations();
        } else {
            console.log("Unexpected HTTP response code in deleteRegistration: " + jqXHR.status);
        }

    }).fail(function(jqXHR, textStatus, errorThrown) {
        console.log("Unexpected HTTP response code in deleteRegistration: " + jqXHR.status);
    });    
}

function renderRegistrations() {
    $("#registrations_table_body").empty();
    fidoRegistrations.forEach((r) => {
        let id = r.id;
        let friendlyName = r.friendlyName || "";
        let brand = r.brand || "";

        $('#registrations_table_body')
            .append($('<tr>')
                .append($('<td>')
                    .text(friendlyName)
                )
                .append($('<td>')
                    .text(brand)
                )
                .append($('<td>')
                    .append($('<button>')
                        .attr("id", id)
                        .click(() => { deleteRegistration(id); })
                        .text('Delete')
                    )
                )
            );
    });
}

function refreshRegistrations() {
    // pull latest registrations from server, then render
    $.ajax({
        type: "PUT",
        url: getRegistrationsAPIAuthSvcURL(),
        data: JSON.stringify({
            action: "getRegistrations"
        }),
        contentType: "application/json; charset=utf-8",
        dataType: "json",
        beforeSend: function(xhr) {
            xhr.setRequestHeader("Accept: application/json");
        }
    }).done(function(data, textStatus, jqXHR) {
        if (jqXHR.status == 200) {
            fidoRegistrations = data;
            renderRegistrations();
        } else {
            console.log("Unexpected HTTP response code in refreshRegistrations: " + jqXHR.status);
        }

    }).fail(function(jqXHR, textStatus, errorThrown) {
        console.log("Unexpected HTTP response code in refreshRegistrations: " + jqXHR.status);
    });

}

function register() {
    // get attestation options
    $.ajax({
        type: "PUT",
        url: getRegistrationsAPIAuthSvcURL(),
        data: JSON.stringify({
            action: "getAttestationOptions"
        }),
        contentType: "application/json; charset=utf-8",
        dataType: "json",
        beforeSend: function(xhr) {
            xhr.setRequestHeader("Accept: application/json");
        }
    }).done(function(data, textStatus, jqXHR) {
        if (jqXHR.status == 200) {
            processAttestationOptionsResponse(data);
        } else {
            console.log("Unexpected HTTP response code in register: " + jqXHR.status);
        }

    }).fail(function(jqXHR, textStatus, errorThrown) {
        console.log("Unexpected HTTP response code in register: " + jqXHR.status);
    });
}

function processAttestationOptionsResponse(options) {
    console.log("Received attestation options: " + JSON.stringify(options));

    let serverOptions = JSON.parse(JSON.stringify(options));

	// remove the status and errorMessage keys
	delete serverOptions["status"];
	delete serverOptions["errorMessage"];
	
	// massage some of the b64u fields into the required ArrayBuffer types
	serverOptions.user.id = new Uint8Array(b64toBA(b64utob64(serverOptions.user.id)));
	serverOptions.challenge = new Uint8Array(b64toBA(b64utob64(serverOptions.challenge)));

	if (serverOptions["excludeCredentials"] != null && serverOptions["excludeCredentials"].length > 0) {
        for (let i = 0; i < serverOptions["excludeCredentials"].length; i++) {
            serverOptions.excludeCredentials[i].id= new Uint8Array(b64toBA(b64utob64(serverOptions.excludeCredentials[i].id)));
        }
	}
	
	var credCreateOptions = { "publicKey": serverOptions };
	console.log("Calling navigator.credentials.create with options: " + JSON.stringify(credCreateOptions));

	// call the webauthn API
	navigator.credentials.create(credCreateOptions).then(
		function(result) {
			// success
			createResponse = result;
								
			// marshall the important parts of the response into an object which we'll later send to the server for validation
			let clientDataJSONB64u = hextob64u(BAtohex(new Uint8Array(createResponse.response.clientDataJSON)));
			let attestationObjectCBORB64u = hextob64u(BAtohex(new Uint8Array(createResponse.response.attestationObject)));
			let clientExtensionResults = createResponse.getClientExtensionResults();
			
			let attestationResponseObject = {};
			attestationResponseObject["id"] = createResponse.id;
			attestationResponseObject["rawId"] = createResponse.id;
			attestationResponseObject["type"] = "public-key";
			attestationResponseObject["response"] = {
					"clientDataJSON": clientDataJSONB64u,
					"attestationObject": attestationObjectCBORB64u
			};
			
			// if there are extensions results, include those
			if (clientExtensionResults != null) {
				attestationResponseObject["getClientExtensionResults"] = clientExtensionResults;
			}
			
			// if transports are available, include them in the response
			if (createResponse.response.getTransports !== undefined) {
				attestationResponseObject["getTransports"] = createResponse.response.getTransports();
			}
			
			// if authenticatorAttachment is available, include it in the response
			if (createResponse.authenticatorAttachment !== null) {
				attestationResponseObject["authenticatorAttachment"] = createResponse.authenticatorAttachment;
			}

            // auto-generate a nickname for this example
            attestationResponseObject["nickname"] = "Passkey created " + (new Date()).toISOString();

            console.log("Final attestationResponseObject: " + JSON.stringify(attestationResponseObject));

            // send it off to the server for validation and registration
            processAttestationResponse(attestationResponseObject);
		}, function(err) {
			// error - can occur for example if the excludeCredentials list already contains
			// a credential registered on this device
			console.log("FIDO2 registration failed: " + err);
		}
	);    
}

function processAttestationResponse(attestationResponseObject) {
    $.ajax({
        type: "PUT",
        url: getRegistrationsAPIAuthSvcURL(),
        data: JSON.stringify({
            action: "processAttestationResponse",
            attestationResponse: attestationResponseObject
        }),
        contentType: "application/json; charset=utf-8",
        dataType: "json",
        beforeSend: function(xhr) {
            xhr.setRequestHeader("Accept: application/json");
        }
    }).done(function(data, textStatus, jqXHR) {
        if (jqXHR.status == 200) {
            fidoRegistrations = data;
            renderRegistrations();
        } else {
            console.log("Unexpected HTTP response code in processAttestationResponse: " + jqXHR.status);
        }

    }).fail(function(jqXHR, textStatus, errorThrown) {
        console.log("Unexpected HTTP response code in processAttestationResponse: " + jqXHR.status);
    });
}

function registrationsStartup() {
    // set up a handler for the register button
    $('#registerButton').click(() => { register(); });

    // populate registrations table
    renderRegistrations();
}
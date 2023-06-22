importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.ibm.security.access.scimclient.ScimClient);
importClass(Packages.com.tivoli.am.fim.fido.mediation.FIDO2RegistrationHelper);
importMappingRule("FIDOInfomapConfig");

function debugLog(s) {
    IDMappingExtUtils.traceString(s);
}

function getInfomapUsername() {
	// get username from already authenticated user
	let result = context.get(Scope.REQUEST,
			"urn:ibm:security:asf:request:token:attribute", "username");
	debugLog("username from existing token: " + result);

	// if not there, try getting from session (e.g. UsernamePassword module)
	if (result == null) {
		result = context.get(Scope.SESSION,
				"urn:ibm:security:asf:response:token:attributes", "username");
		debugLog("username from session: " + result);
	}
	if (result != null) {
		// make it a javascript string - this prevents stringify issues later
		result = '' + result;
	}
	return result;
}

/**
 * Utility to get the user unique id from the the Infomap context
 */
function getInfomapUserUniqueID() {
	let result = null;
	let username = getInfomapUsername();
	if (username != null) {
		result = ScimClient.computeIDForUsername(username);
	}
	if (result != null) {
		// make it a javascript string - this prevents stringify issues later
		result = '' + result;
	}
	return result;
}

// returns JSON array of the current user's registrations
function getRegistrations(frh) {
    let result = [];

    let userRegistrations = frh.getRegistrationsByUsername(getInfomapUsername());
    if (userRegistrations != null && userRegistrations.size() > 0) {
        for (var i = userRegistrations.iterator(); i.hasNext(); ) {
            let fr = i.next();
            if (fr.getRpId().equals(RPID)) {
                // best practice here to send back pure JSON, and only the fields needed at the client
                result.push({
                    id: ''+fr.getCredentialId(),
                    friendlyName: (fr.getFriendlyName() != null ? '' + fr.getFriendlyName(): ''),
                    brand: (fr.getMetadataDescription() != null ? '' + fr.getMetadataDescription(): '')
                });
            }
        }
    }

    return result;
}

function deleteRegistration(frh, id) {
    fr = frh.getRegistrationByCredId(id);
    if (fr != null) {
        // first check it is owned by the current user before deleting!
        if (fr.getUsername() != null && fr.getUsername().equals(getInfomapUsername())) {
            debugLog("Deleting registration with id: " + id + " for user: " + fr.getUsername());
            frh.removeRegistration(fr.getRpId(), id);
        }
    }    
}

function sendJSONResponse(jObj) {
    page.setValue("/authsvc/authenticator/fido_infomap/jsonresponse.html");
    macros.put("@AUTHSVC_JSON_RESPONSE@", JSON.stringify(jObj));
    responseProcessed = true;
}

function sendErrorResponse(str) {
    page.setValue("/authsvc/authenticator/fido_infomap/error.html");
    macros.put("@ERROR_MSG@", str);
    responseProcessed = true;
}

/*
 * Main body starts here
 */
var frh = new FIDO2RegistrationHelper();
var lfc = fido2ClientManager.getClient(RPID);
var responseProcessed = false;
   
// you have to be logged in to use this infomap
if (getInfomapUsername() == null) {
    sendErrorResponse("No logged in");
} else {
    // figure out what we are doing for this invocation
    var action = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "action");

    // perform any specific action first
    if (action != null) {
        if (action.equals("deleteRegistration")) {
            let credId = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "id");
            if (credId != null) {
                deleteRegistration(frh, credId);
                sendJSONResponse(getRegistrations(frh));
            }
        } else if (action.equals("getAttestationOptions")) {
            // get options and return as JSON
            let attestationOptionsStr = lfc.attestationOptions(JSON.stringify({
                username: getInfomapUsername(),
                displayName: getInfomapUsername(),
                authenticatorSelection: {
                    residentKey: "required",
                    userVerification: "required"
                },
                attestation: "direct"
            }));
            debugLog("attestationOptionsStr: " + attestationOptionsStr);
            sendJSONResponse(JSON.parse(''+attestationOptionsStr));
        } else if (action.equals("processAttestationResponse")) {
            var attestationResponseStr = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "attestationResponse");
            if (attestationResponseStr != null) {
                let attestationResultStr = lfc.attestationResult(attestationResponseStr);
                debugLog("attestationResultStr: " + attestationResultStr);
            } else {
                debugLog("processAttestationResponse action did not contain attestationResponse");
            }
            sendJSONResponse(getRegistrations(frh));
        }
    } 

    // default action is to populate the registrations page
    if (!responseProcessed) {
        let registrations = getRegistrations(frh);
        page.setValue("/authsvc/authenticator/fido_infomap/registrations.html");
        macros.put("@FIDO_REGISTRATIONS_JSON@", JSON.stringify(registrations));
    }
}


// this infomap never logs in
success.setValue(false);
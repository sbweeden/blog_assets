importClass(Packages.com.tivoli.am.fim.fido.mediation.FIDO2RegistrationHelper);
importMappingRule("FIDOInfomapUtils");


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


/*
 * Main body starts here
 */
var frh = new FIDO2RegistrationHelper();
var lfc = fido2ClientManager.getClient(RPID);
   
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
        } else if (action.equals("getRegistrations")) {
            // get registrations and return as JSON
            sendJSONResponse({
                status: 'ok',
                fidoRegistrations: getRegistrations(frh)
            });
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
                let attestationResult = JSON.parse(''+attestationResultStr);
                if (attestationResult.status == 'ok') {
                    sendJSONResponse({
                        status: 'ok',
                        fidoRegistrations: getRegistrations(frh)
                    });
                } else {
                    sendJSONResponse(attestationResult);
                }
            } else {
                debugLog("processAttestationResponse action did not contain attestationResponse");
            }
            
        }
    } 

    // default action is to populate the registrations page
    if (!responseProcessed) {
        page.setValue("/authsvc/authenticator/fido_infomap/registrations.html");
        macros.put("@ESCAPED_FIDO_REGISTRATIONS_JSON@", JSON.stringify({
            status: 'ok',
            username: getInfomapUsername(),
            fidoRegistrations: getRegistrations(frh)
        }));
    }
}


// this infomap never logs in
success.setValue(false);
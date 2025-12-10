// isv_fido_registrations_for_user.js

//
// Given a username, return a summary of all the users passkey registrations
//


// get configuration in place
require('dotenv').config();

const fs = require('fs');

// read the username as a command line parameter, with fallback to the config file username
let username = process.argv[2];
if (username == null) {
    // exit after printing an error saying that username is required
    console.error("Usage: node isv_fido_registrations_for_user.js <username>");
    process.exit(1);
}

//
// The api client minimally needs the following entitlements
// readEnrollMFAMethodAnyUser
// readUsers
//
let apiClientID = process.env.API_CLIENT_ID;
let apiClientSecret = process.env.API_CLIENT_SECRET;
let tenant = process.env.ISV_TENANT;
let tokenEndpoint = "https://" + tenant + "/oauth2/token";
let errorResponse = false;
let rspStatus = null;

// Main entry point logic starts here
// get an api client access token
console.log("Fetching API client access token");
let apiAccessToken = null;
fetch(
    tokenEndpoint,
    {
        method: "POST",
        headers: {
            "Accept": "application/json"
        },
        body: new URLSearchParams({
            grant_type: "client_credentials",
            client_id: apiClientID,
            client_secret: apiClientSecret
        })
    }
).then((rsp) => {
    errorResponse = !rsp.ok;
    rspStatus = rsp.status;
    return rsp.json();
}).then((jsonRsp) => {
    if (errorResponse) {
        throw new Error("Unexpected HTTP response code fetching API client access token: " + rspStatus + " Body: " + JSON.stringify(jsonRsp));
    }
    // error check
    if (jsonRsp.access_token == null) {
        throw new Error("Unable to retrieve API access token");
    }
    return jsonRsp.access_token;
}).then((at) => {
    apiAccessToken = at;
    // lookup the user id
    console.log("Lookup up user: " + username);
    return fetch(
        "https://" + tenant + "/v2.0/Users?" + new URLSearchParams({ "filter" : 'userName eq "' + username + '"' }),
        {
            method: "GET",
            headers: {
                "Accept": "application/scim+json",
                "Authorization": "Bearer " + apiAccessToken
            }
        }
    );
}).then((rsp) => {
    errorResponse = !rsp.ok;
    rspStatus = rsp.status;
    return rsp.json();
}).then((scimResponse) => {
    if (errorResponse) {
        throw new Error("Unexpected HTTP response code performing user lookup: " + rspStatus + " Body: " + JSON.stringify(scimResponse));
    }

    // check we found exactly one user
    if (scimResponse && scimResponse.totalResults == 1) {
        return scimResponse.Resources[0].id;
    } else {
        throw new Error("Unable to find user: " + username + " scimResponse: " + JSON.stringify(scimResponse));
    }
}).then((userId) => {
    console.log("User ID: " + userId);

	let search = 'userId="' + userId + '"';
	// to futher filter results for just my rpId matching the tenant hostname, add this
	search += '&attributes/rpId="'+process.env.ISV_TENANT+'"';
    return fetch(
        "https://" + tenant + "/v2.0/factors/fido2/registrations?" + new URLSearchParams({ "search" : search}),
        {
            method: "GET",
            headers: {
                "Accept": "application/json",
                "Authorization": "Bearer " + apiAccessToken
            }
        }
    );
}).then((rsp) => {
    errorResponse = !rsp.ok;
    rspStatus = rsp.status;
    return rsp.json();
}).then((regResponse) => {
    if (errorResponse) {
        throw new Error("Unexpected HTTP response code performing factors lookup: " + rspStatus + " Body: " + JSON.stringify(regResponse));
    }
    // full registrations response
    //console.log(JSON.stringify(regResponse, null, 2));

    // log a summary of FIDO registrations for the user
    console.log("Username: " + username + " total FIDO registrations: " + regResponse.total);
    if (regResponse.total > 0) {
        regResponse.fido2.forEach(r => {
            if (r.attributes.attestationFormat == "fido-u2f") {
                console.log("Nickname: " + r.attributes.nickname + " U2F registration" + " Description: " + (r.attributes.description != null ? r.attributes.description : "No description available"));
            } else {
                console.log("Nickname: " + r.attributes.nickname + " AAGUID: " + r.attributes.aaGuid + " Description: " + (r.attributes.description != null ? r.attributes.description : "No description available"));
            }
            
        });
    }

}).catch((err) => {
    console.log("Error: " + err);
});
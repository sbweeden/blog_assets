// isv_jwt_bearer.js

// get configuration in place
require('dotenv').config();

const fs = require('fs');
const jsrsasign = require('jsrsasign');
const { v4: uuidv4 } = require('uuid');

let JWTBEARER_PRIVATE_KEY="jwtbearerPrivate.pem";
let JWTBEARER_PRIVATE_KEY_KID="jwtbearer";

//
// Main entry point logic starts here
//

// check that the private key file exists
if (!fs.existsSync(JWTBEARER_PRIVATE_KEY)) {
    console.log("Please run the create_keys.js file first to create a keypair for the jwtbearer grant type flow. Additionally you will need to host the public key or certificate at a JWKS endpoint and configure the OIDC client application to use that JWKS endpoint.");
} else {
    // read in the private key file and other configuration parameters
    let prvKeyPEM = fs.readFileSync(JWTBEARER_PRIVATE_KEY).toString();

    let oidcClientID = process.env.OIDC_CLIENT_ID;
    let oidcClientSecret = process.env.OIDC_CLIENT_SECRET;
    let apiClientID = process.env.API_CLIENT_ID;
    let apiClientSecret = process.env.API_CLIENT_SECRET;
    let tenant = process.env.ISV_TENANT;
    let username = process.env.USERNAME;
    let lifetimeSec=120;
    let skewSec=10; 
    let tokenEndpoint = "https://" + tenant + "/oauth2/token";
    let errorResponse = false;
    let rspStatus = null;


    // get an api client access token
    console.log("Fetching API client access token");
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
    }).then((apiAccessToken) => {
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
        // build the jwt bearer assertion
        let prvKey = jsrsasign.KEYUTIL.getKey(prvKeyPEM);
        let nowSec = Math.floor(new Date().getTime()/1000);
        
        let jwtHeader = { alg: "ES256", typ: "JWT", kid: JWTBEARER_PRIVATE_KEY_KID};
        let jwtClaims = {
            iss: "https://" + tenant,
            aud: tokenEndpoint,
            sub: userId,
            scope: "openid",
            nbf: (nowSec-skewSec),
            iat: nowSec,
            exp: (nowSec+skewSec+lifetimeSec),
            jti: uuidv4()
        };
        
        let sHeader = JSON.stringify(jwtHeader);
        let sPayload = JSON.stringify(jwtClaims);
        return jsrsasign.KJUR.jws.JWS.sign(jwtHeader.alg, sHeader, sPayload, prvKey);
    }).then((assertion) => {
        console.log("Performing jwt bearer grant type flow");
        return fetch(
            tokenEndpoint,
             {
                 method: "POST",
                 headers: {
                     "Accept": "application/json",
                 },
                 body: new URLSearchParams({
                    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    client_id: oidcClientID,
                    client_secret: oidcClientSecret,
                    assertion: assertion
                })
             }
         );
    }).then((rsp) => {
        errorResponse = !rsp.ok;
        rspStatus = rsp.status;
        return rsp.json();
    }).then((jsonRsp) => {
            if (errorResponse) {
                throw new Error("Unexpected HTTP response code performing jwt bearer grant type flow: " + rspStatus + " Body: " + JSON.stringify(jsonRsp));
            }

             //console.log("Received token response: " + JSON.stringify(jsonRsp));
         
             // do more here
             if (jsonRsp.access_token) {
                 let sessionEndpoint = "https://" + tenant + "/v1.0/auth/session";
                 console.log('Redirect the browser to: ' + sessionEndpoint + '?access_token=' + jsonRsp.access_token + '&redirect_url=/usc');
             } else {
                throw new Error("No access token found in jwt bearer flow token response");
             }
    }).catch((e) => {
        console.log(e);
    });
}

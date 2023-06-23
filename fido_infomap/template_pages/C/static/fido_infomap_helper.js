// set of client-side helper functions for FIDO capabilities

// assumes availability of jquery and jsrrsasign libraries as includes before this one

// couple of global vars for WebAuthn feature discovery - call performWebAuthnFeatureDiscovery (promise-based) to populate
var isUVPAA = false;
var isAutofillAvailable = false; 

function htmlEncode(value){
    if (value) {
        return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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

function showDiv(id) {
    document.getElementById(id).style.display = "block";
}

function hideDiv(id) {
    document.getElementById(id).style.display = "none";
}

function getBaseURL() {
    var locationHostPort = location.hostname+(location.port ? ':'+location.port: ''); 
    var baseURL = location.protocol+'//'+locationHostPort;

    return baseURL;
}

function renderFeatureTable() {
    // if the table is present, populate it with rows
    let featureTBody = $('#webauthn_feature_table_body');
    if (featureTBody != null) {
        rowData = [
            {
                feature: "isWebAuthnAvailable",
                value: webAuthnAvailable()
            },
            {
                feature: "isUVPAA",
                value: isUVPAA
            },
            {
                feature: "isAutofillAvailable",
                value: isAutofillAvailable
            }
        ];
        $('#webauthn_feature_table_body').empty();
        rowData.forEach((r) => {
            $('#webauthn_feature_table_body')
            .append($('<tr>')
                .append($('<td>')
                    .text(r.feature)
                )
                .append($('<td>')
                    .text(''+r.value)
                )
            );

        });
    }
}

function webAuthnAvailable() {
    return !(typeof(PublicKeyCredential) == undefined);
}

function performWebAuthnFeatureDiscovery() {
    let allPromises = [];
    if (webAuthnAvailable()) {
        isUVPAA = false;
        isAutofillAvailable = false; 
        allPromises.push(
            PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
            .then((x) => { isUVPAA = x; })
            .catch((e) => { console.log("Error calling PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable: " + e); })
        );
        if (PublicKeyCredential.isConditionalMediationAvailable != null) {
            allPromises.push(
                PublicKeyCredential.isConditionalMediationAvailable()
                .then((x) => { isAutofillAvailable = x; })
                .catch((e) => { console.log("Error calling PublicKeyCredential.isConditionalMediationAvailable: " + e); })
            );    
        }
    }
    // now return all the promises
    return Promise.all(allPromises);
}



/***************************
 * Common variables and functions
***************************/

//var passkeyregThemeId="YOUR_THEME_ID";
var passkeyregThemeId="949743b2-a96c-40e0-853e-7bfc8971e17b";


const LS_AMBIENT_CREDENTIALS = "ambientCredentials";
var ac = null;

function getAmbientCredentials() {
    let acStr = localStorage.getItem(LS_AMBIENT_CREDENTIALS);
    return (acStr == null ? { users: {} } : JSON.parse(acStr));
}

function storeAmbientCredentials() {
    localStorage.setItem(LS_AMBIENT_CREDENTIALS, JSON.stringify(ac));
}

function htmlDecode(s) {
	if (s) {
		return s.replace(/&quot;/g, '"').replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&amp;/g, '&');
		
	} else {
		return '';
	}
}

// Utility function to remove css class if element contains it
function elementsToHide(elementsArray) {
    elementsArray.forEach((el) => {
      if (el.classList.contains('block')) {
        el.classList.remove('block');
      }
    });
}

function showDiv(id) {
    var mydiv = document.getElementById(id);
    if (mydiv != null) {
        mydiv.style.display = "block";
    }
}

function commonOnLoad(scriptElement) {
    ac = getAmbientCredentials();
}

var isUVPAA;
var isAutofillAvailable;
var isSafariFlag;
var doPasskeysWorkHere;

function webAuthnAvailable() {
    return !(typeof(PublicKeyCredential) == undefined);
}


// Safari 3.0+ "[object HTMLElementConstructor]"
function isSafari() {
    return /constructor/i.test(window.HTMLElement) || (function(p) {
        return p.toString() === "[object SafariRemoteNotification]";
    })(!window['safari'] || (typeof safari !== 'undefined' && safari.pushNotification));
}

function isLinux() {
    // this relies on https://github.com/bestiejs/platform.js which must be sourced (e.g. via https://cdnjs.cloudflare.com/ajax/libs/platform/1.3.6/platform.min.js)
    //console.log("platform: " + (platform != null ? JSON.stringify(platform) : "unknown"));
    return (platform != null && platform.os != null && platform.os.family != null && platform.os.family.toLowerCase() == "linux");
}

/**
 *  This function is designed to detect if we are running on a browser platform
 *  capable of WebAuthn login. In particular it is designed to filter out web widgets
 *  that are causing trouble on Mac platforms with thick Microsoft clients like
 *  Outlook, Teams, and even the Apple Internet Accounts integration for Microsoft Exchange.
 *  In those cases, and other cases where WebAuthn won't work, we should see this resolving to false.
 */
function clientSupportsPasskeys() {
    return new Promise((resolve, reject) => {
        
        try {
            // if not a browser, then no
            if (!window) {
                resolve(false);
            }

            // if PublicKeyCredential is not available, then no
            else if (typeof(PublicKeyCredential) == undefined) {
                resolve(false);
            } 

            // if this is a browser on Linux, say yes
            // we know Linux does not have uvpaa, however browsers on Linux support FIDO
            else if (isLinux()) {
                console.log("clientSupportsPasskeys: Detected Linux, resolving to true.");
                resolve(true);
            }
            // otherwise resolve based on whether or not PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable returns true
            // since web widget returns false for this (at least on Mac), and modern OSs other than Linux covered above should
            // return true
            else {
                PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
                .then((isUVPAA) => { console.log("isUserVerifyingPlatformAuthenticatorAvailable returned: " + isUVPAA); resolve(isUVPAA); })
                .catch((e) => { resolve(false); })
            }
        } catch (err) {
            resolve(false);
        }
    });
}  

function performWebAuthnFeatureDiscovery() {
    let allPromises = [];

    isSafariFlag = isSafari();

    if (webAuthnAvailable()) {
        isUVPAA = false;
        isAutofillAvailable = false; 
        doPasskeysWorkHere = false;

        allPromises.push(
            clientSupportsPasskeys()
            .then((x) => {
                doPasskeysWorkHere = x;
            }).catch((e) => {
                console.log("Error calling clientSupportsPasskeys: " + e); 
            })
        );

        // if the new getClientCapabilities API is available, prefer that
        if (typeof PublicKeyCredential.getClientCapabilities != 'undefined') {
            console.log("Using PublicKeyCredential.getClientCapabilities for discovery");
            allPromises.push(
                PublicKeyCredential.getClientCapabilities()
                .then((x) => { 
                    isUVPAA = (x.userVerifyingPlatformAuthenticator == true);
                    isAutofillAvailable = (x.conditionalMediation == true);
                }).catch((e) => { 
                    console.log("Error calling PublicKeyCredential.getClientCapabilities: " + e); 
                })
            );

        } else {
            console.log("Using WebAuthn L2 discovery APIs");
            // use original discovery APIs
            if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable != 'undefined') {
                allPromises.push(
                    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
                    .then((x) => { isUVPAA = x; })
                    .catch((e) => { console.log("Error calling PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable: " + e); })
                );
            }
            if (typeof PublicKeyCredential.isConditionalMediationAvailable != 'undefined') {
                allPromises.push(
                    PublicKeyCredential.isConditionalMediationAvailable()
                    .then((x) => { isAutofillAvailable = x; })
                    .catch((e) => { console.log("Error calling PublicKeyCredential.isConditionalMediationAvailable: " + e); })
                );    
            }
        }

    }
    // now return all the promises
    return Promise.all(allPromises);
}

//
// Utility to read client-side cookie value. We use this to retrieve the 
// workflowcallbackurl cookie that is set in workflow custom page (4)
// prior to initiating inline MFA registration since inline MFA registration
// does not have a native way of doing this.
//
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

// 
// Uses the workflow callback URL (temporarily stored in a cookie)
// to exit out of the inline MFA policy. Deletes the cookie as we
// go.
//
function abortPasskeyRegistration() {
    let redirectURL = getCookie('workflowcallbackurl');
    document.cookie = "workflowcallbackurl=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    window.location.replace(redirectURL);
}


/***************************
 * Used by custom_page1.html
***************************/

function onLoadCustomPage1(scriptElement) {
    commonOnLoad(scriptElement);
    let tagJson = JSON.parse(scriptElement.textContent);
    document.cookie = "workflowcallbackurl=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    console.log("passkeyreg workflow complete, redirecting to: " + htmlDecode(tagJson.target));
    window.location.replace(htmlDecode(tagJson.target));
}

/***************************
 * Used by custom_page2.html
***************************/

function onLoadCustomPage2(scriptElement) {
    commonOnLoad(scriptElement);
    performWebAuthnFeatureDiscovery().then(() => {
        document.getElementById("discoveryInfo").value = JSON.stringify({
            "cookie": document.cookie,
            "isSafari": isSafariFlag,
            "doPasskeysWorkHere": doPasskeysWorkHere,
            "isUVPAA": isUVPAA,
            "isAutofillAvailable": isAutofillAvailable,
            "ambientCredentials": getAmbientCredentials()
        });

        document.getElementById("discoveryForm").submit();
    });
}

/***************************
 * Used by custom_page3.html
***************************/


// already html encoded
var username = null;




function registerUVPA() {
    document.getElementById("passkeyOperation").value = "register";
    document.getElementById("passkeyForm").submit();
}

function notNowUVPAA() {
    document.getElementById("passkeyOperation").value = "skip";
    document.getElementById("passkeyForm").submit();
}

function noUVPAA() {
    // update localStorage to indicate we never want to do this on this device
    if (!ac.users[username]) {
        ac.users[username] = {};
    }
    ac.users[username].useFIDO = false;
    storeAmbientCredentials();

    document.getElementById("passkeyOperation").value = "skip";
    document.getElementById("passkeyForm").submit();
}

function onLoadCustomPage3(scriptElement) {
    commonOnLoad(scriptElement);
    let tagJson = JSON.parse(scriptElement.textContent);
    username = htmlDecode(tagJson.username)
    document.getElementById("usernamediv").innerText = username;

    // add button click handlers
    let notNowButton = document.getElementById("notNowButton");
    if (notNowButton != null) {
        notNowButton.addEventListener('click', notNowUVPAA);
    }
    let registerButton = document.getElementById("registerButton");
    if (registerButton != null) {
        registerButton.addEventListener('click', registerUVPA);
    }
    let neverButton = document.getElementById("neverButton");
    if (neverButton != null) {
        neverButton.addEventListener('click', noUVPAA);
    }
    

    showDiv("msgdiv");
}
/***************************
 * Used by custom_page4.html
***************************/


function onLoadCustomPage4(scriptElement) {
    commonOnLoad(scriptElement);
    let tagJson = JSON.parse(scriptElement.textContent);

    document.cookie="workflowcallbackurl="+tagJson.workflowCallbackURL+";path=/";
    var redirectURL = htmlDecode(tagJson.passkeyURL)+"&Target="+tagJson.workflowCallbackURL
    window.location.replace(redirectURL);
}

/***************************
 * Used by enrollment_success.html
***************************/

function esShowAnotherMethodLink (showAnotherMethod) {
    if (typeof showAnotherMethod !== 'undefined' && showAnotherMethod === "false"){
      document.getElementById("use-another-method-link").classList.add('hidden');
    }
}

function esAddMore() {
    document.getElementById("add-another-method-form").submit();
}

function onLoadEnrollmentSuccess(scriptElement) {
    commonOnLoad(scriptElement);
    let tagJson = JSON.parse(scriptElement.textContent);

    let showAnotherMethod = tagJson.showAnotherMethod;
    let showInfo = tagJson.showInfo;
    let doneAllowed = tagJson.doneAllowed;

    let addMoreHref = document.getElementById("addMoreHref");
    if (addMoreHref != null) {
        addMoreHref.href = "javascript:void(0)";
        addMoreHref.addEventListener('click', esAddMore);
    }

    esShowAnotherMethodLink(showAnotherMethod);

    if (!doneAllowed) {
        document.getElementById("done-button").disabled = true;
    }
    
    if (!showInfo) {
        document.getElementById("setup-info").style.display = 'none';
    }
}

/***************************
 * Used by fido2_enrollment.html
 * Requires jsrsasign and CBOR 
***************************/

var tagJsonFido2Enrollment;
var attestationOptions;
var enrollCredInfo;

/*
Following code provide all the underlying capabilities required to introspect the registration
response and determine the AAGUID and declared sync status of the registration. This allows us to 
implement an auto-naming feature for the nickname generation.
*/


/**
 * Extracts the bytes from an array beginning at index start, and continuing until 
 * index end-1 or the end of the array is reached. Pass -1 for end if you want to 
 * parse till the end of the array.
 */
function bytesFromArray(o, start, end) {
    // o may be a normal array of bytes, or it could be a JSON encoded Uint8Array
    var len = o.length;
    if (len == null) {
        len = Object.keys(o).length;
    }
    
    var result = [];
    for (var i = start; (end == -1 || i < end) && (i < len); i++) {
        result.push(o[i]);
    }
    return result;
}

/**
 * Convert a 4-byte array to a uint assuming big-endian encoding
 * 
 * @param buf
 */
function bytesToUInt32BE(buf) {
    var result = 0;
    if (buf != null && buf.length == 4) {
        result = ((buf[0] & 0xFF) << 24) | ((buf[1] & 0xFF) << 16) | ((buf[2] & 0xFF) << 8) | (buf[3] & 0xFF);
        return result;
    }
    return result;
}

function unpackAuthData(authDataBytes) {
    console.log("unpackAuthData enter");
    var result = { 
        "status": false, 
        "rawBytes": null,
        "rpIdHashBytes": null, 
        "flags": 0, 
        "counter": 0, 
        "attestedCredData": null,
        "extensions": null
    };
    
    result["rawBytes"] = authDataBytes;
    
    if (authDataBytes != null && authDataBytes.length >= 37) {
        result["rpIdHashBytes"] = bytesFromArray(authDataBytes, 0, 32);
        result["flags"] = authDataBytes[32];
        result["counter"] = bytesToUInt32BE(bytesFromArray(authDataBytes, 33, 37));
                
        var nextByteIndex = 37;
        
        // check flags to see if there is attested cred data and/or extensions
        
        // bit 6 of flags - Indicates whether the authenticator added attested credential data.
        if (result["flags"] & 0x40) {
            result["attestedCredData"] = {};
            
            // are there enough bytes to read aaguid?
            if (authDataBytes.length >= (nextByteIndex + 16)) {
                result["attestedCredData"]["aaguid"] = bytesFromArray(authDataBytes, nextByteIndex, (nextByteIndex+16));
                nextByteIndex += 16;
                
                // are there enough bytes for credentialIdLength?
                if (authDataBytes.length >= (nextByteIndex + 2)) {
                    var credentialIdLengthBytes = bytesFromArray(authDataBytes, nextByteIndex, (nextByteIndex+2));
                    nextByteIndex += 2;
                    var credentialIdLength = credentialIdLengthBytes[0] * 256 + credentialIdLengthBytes[1] 
                    result["attestedCredData"]["credentialIdLength"] = credentialIdLength;
                    
                    // are there enough bytes for the credentialId?
                    if (authDataBytes.length >= (nextByteIndex + credentialIdLength)) {
                        result["attestedCredData"]["credentialId"] = bytesFromArray(authDataBytes, nextByteIndex, (nextByteIndex+credentialIdLength));
                        nextByteIndex += credentialIdLength;
                        
                        var remainingBytes = bytesFromArray(authDataBytes, nextByteIndex, -1);
                        
                        //
                        // try CBOR decoding the remaining bytes. 
                        // NOTE: There could be both credentialPublicKey and extensions objects
                        // so we use this special decodeVariable that Shane wrote to deal with
                        // remaining bytes.
                        //
                        try {
                            var decodeResult = CBOR.decodeVariable((new Uint8Array(remainingBytes)).buffer);
                            result["attestedCredData"]["credentialPublicKey"] = decodeResult["decodedObj"];
                            nextByteIndex += (decodeResult["offset"] == -1 ? remainingBytes.length : decodeResult["offset"]);
                        } catch (e) {
                            console.log("Error CBOR decoding credentialPublicKey: " + e);
                            nextByteIndex = -1; // to force error checking
                        }
                    } else {
                        console.log("unPackAuthData encountered authDataBytes not containing enough bytes for credentialId in attested credential data");
                    }					
                } else {
                    console.log("unPackAuthData encountered authDataBytes not containing enough bytes for credentialIdLength in attested credential data");
                }				
            } else {
                console.log("unPackAuthData encountered authDataBytes not containing enough bytes for aaguid in attested credential data");
            }
        }
        
        // bit 7 of flags - Indicates whether the authenticator has extensions.
        if (nextByteIndex > 0 && result["flags"] & 0x80) {
            try {
                result["extensions"] = CBOR.decode((new Uint8Array(bytesFromArray(authDataBytes, nextByteIndex, -1))).buffer);
                // must have worked
                nextByteIndex = authDataBytes.length;
            } catch (e) {
                console.log("Error CBOR decoding extensions");
            }
        }
        
        // we should be done - make sure we processed all the bytes
        if (nextByteIndex == authDataBytes.length) {
            result["status"] = true;
        } else {
            console.log("Remaining bytes in unPackAuthData. nextByteIndex: " + nextByteIndex + " authDataBytes.length: " + authDataBytes.length);
        }
    } else {
        console.log("unPackAuthData encountered authDataBytes not at least 37 bytes long. Actual length: " + authDataBytes.length);
    }

    console.log("unpackAuthData returning: " + JSON.stringify(result));

    return result;
}   

/**
* Build a human-readable string from the aaguid bytes
*/
function aaguidBytesToUUID(b) {
    var result = null;
    if (b != null && b.length == 16) {
        var s = BAtohex(b).toUpperCase();
        result = s.substring(0,8).concat("-",s.substring(8,12),"-",s.substring(12,16),"-",s.substring(16,20),"-",s.substring(20,s.length));
    }
    return result;
}

// acknowledegement for this idea to: https://passkeynametool.identitystandards.ms/

//
// see github repo https://github.com/passkeydeveloper/passkey-authenticator-aaguids
// this is combined_aaguid.json with all the icon stuff removed to keep it smaller.
// to do this:
// curl "https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/combined_aaguid.json" | jq -c 'del(.[].icon_light) | del(.[].icon_dark)'
//
const aaguidLookupTable = {"fcb1bcb4-f370-078c-6993-bc24d0ae3fbe":{"name":"Ledger Nano X FIDO2 Authenticator"},"4d41190c-7beb-4a84-8018-adf265a6352d":{"name":"Thales IDPrime FIDO Bio"},"2772ce93-eb4b-4090-8b73-330f48477d73":{"name":"Security Key NFC by Yubico - Enterprise Edition Preview"},"6dae43be-af9c-417b-8b9f-1b611168ec60":{"name":"Dapple Authenticator from Dapple Security Inc."},"5626bed4-e756-430b-a7ff-ca78c8b12738":{"name":"VALMIDO PRO FIDO"},"260e3021-482d-442d-838c-7edfbe153b7e":{"name":"Feitian ePass FIDO2-NFC Plus Authenticator"},"95e4d58c-056e-4a65-866d-f5a69659e880":{"name":"TruU Windows Authenticator"},"9c835346-796b-4c27-8898-d6032f515cc5":{"name":"Cryptnox FIDO2"},"0d9b2e56-566b-c393-2940-f821b7f15d6d":{"name":"Excelsecu eSecu FIDO2 Pro Security Key"},"c5ef55ff-ad9a-4b9f-b580-adebafe026d0":{"name":"YubiKey 5 Series with Lightning"},"2194b428-9397-4046-8f39-007a1605a482":{"name":"IDPrime 931 Fido"},"39a5647e-1853-446c-a1f6-a79bae9f5bc7":{"name":"IDmelon"},"664d9f67-84a2-412a-9ff7-b4f7d8ee6d05":{"name":"OpenSK authenticator"},"3789da91-f943-46bc-95c3-50ea2012f03a":{"name":"NEOWAVE Winkeo FIDO2"},"fa2b99dc-9e39-4257-8f92-4a30d23c4118":{"name":"YubiKey 5 Series with NFC"},"341e4da9-3c2e-8103-5a9f-aad887135200":{"name":"Ledger Nano S FIDO2 Authenticator"},"69700f79-d1fb-472e-bd9b-a3a3b9a9eda0":{"name":"Pone Biometrics OFFPAD Authenticator"},"89b19028-256b-4025-8872-255358d950e4":{"name":"Sentry Enterprises CTAP2 Authenticator"},"4e768f2c-5fab-48b3-b300-220eb487752b":{"name":"Hideez Key 4 FIDO2 SDK"},"47ab2fb4-66ac-4184-9ae1-86be814012d5":{"name":"Security Key NFC by Yubico - Enterprise Edition"},"931327dd-c89b-406c-a81e-ed7058ef36c6":{"name":"Swissbit iShield Key FIDO2"},"8d1b1fcb-3c76-49a9-9129-5515b346aa02":{"name":"IDEMIA ID-ONE Card"},"454e5346-4944-4ffd-6c93-8e9267193e9a":{"name":"Ensurity ThinC"},"e1a96183-5016-4f24-b55b-e3ae23614cc6":{"name":"ATKey.Pro CTAP2.0"},"9d3df6ba-282f-11ed-a261-0242ac120002":{"name":"Arculus FIDO2/U2F Key Card"},"fbefdf68-fe86-0106-213e-4d5fa24cbe2e":{"name":"Excelsecu eSecu FIDO2 NFC Security Key"},"62e54e98-c209-4df3-b692-de71bb6a8528":{"name":"YubiKey 5 FIPS Series with NFC Preview"},"ab32f0c6-2239-afbb-c470-d2ef4e254db7":{"name":"TOKEN2 FIDO2 Security Key"},"973446ca-e21c-9a9b-99f5-9b985a67af0f":{"name":"ACS FIDO Authenticator Card"},"74820b05-a6c9-40f9-8fb0-9f86aca93998":{"name":"SafeNet eToken Fusion"},"1105e4ed-af1d-02ff-ffff-ffffffffffff":{"name":"Egomet FIDO2 Authenticator for Android"},"08987058-cadc-4b81-b6e1-30de50dcbe96":{"name":"Windows Hello"},"a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa":{"name":"Security Key NFC by Yubico"},"0acf3011-bc60-f375-fb53-6f05f43154e0":{"name":"Nymi FIDO2 Authenticator"},"d91c5288-0ef0-49b7-b8ae-21ca0aa6b3f3":{"name":"KEY-ID FIDO2 Authenticator"},"4c50ff10-1057-4fc6-b8ed-43a529530c3c":{"name":"ImproveID Authenticator"},"ee041bce-25e5-4cdb-8f86-897fd6418464":{"name":"Feitian ePass FIDO2-NFC Authenticator"},"efb96b10-a9ee-4b6c-a4a9-d32125ccd4a4":{"name":"Safenet eToken FIDO"},"4b3f8944-d4f2-4d21-bb19-764a986ec160":{"name":"KeyXentic FIDO2 Secp256R1 FIDO2 CTAP2 Authenticator"},"4c0cf95d-2f40-43b5-ba42-4c83a11c04ba":{"name":"Feitian BioPass FIDO2 Pro Authenticator"},"5343502d-5343-5343-6172-644649444f32":{"name":"ESS Smart Card Inc. Authenticator"},"09591fc6-9811-48f7-8f57-b9f23df6413f":{"name":"Pone Biometrics OFFPAD Authenticator"},"7e3f3d30-3557-4442-bdae-139312178b39":{"name":"RSA DS100"},"73bb0cd4-e502-49b8-9c6f-b59445bf720b":{"name":"YubiKey 5 FIPS Series"},"149a2021-8ef6-4133-96b8-81f8d5b7f1f5":{"name":"Security Key by Yubico with NFC"},"175cd298-83d2-4a26-b637-313c07a6434e":{"name":"Chunghwa Telecom FIDO2 Smart Card Authenticator"},"3b1adb99-0dfe-46fd-90b8-7f7614a4de2a":{"name":"GoTrust Idem Key FIDO2 Authenticator"},"998f358b-2dd2-4cbe-a43a-e8107438dfb3":{"name":"OnlyKey Secp256R1 FIDO2 CTAP2 Authenticator"},"61250591-b2bc-4456-b719-0b17be90bb30":{"name":"eWBM eFPA FIDO2 Authenticator"},"f8a011f3-8c0a-4d15-8006-17111f9edc7d":{"name":"Security Key by Yubico"},"8976631b-d4a0-427f-5773-0ec71c9e0279":{"name":"Solo Tap Secp256R1 FIDO2 CTAP2 Authenticator"},"516d3969-5a57-5651-5958-4e7a49434167":{"name":"SmartDisplayer BobeePass FIDO2 Authenticator"},"a02167b9-ae71-4ac7-9a07-06432ebb6f1c":{"name":"YubiKey 5 Series with Lightning"},"2c0df832-92de-4be1-8412-88a8f074df4a":{"name":"Feitian FIDO Smart Card"},"970c8d9c-19d2-46af-aa32-3f448db49e35":{"name":"WinMagic FIDO Eazy - TPM"},"c5703116-972b-4851-a3e7-ae1259843399":{"name":"NEOWAVE Badgeo FIDO2"},"c80dbd9a-533f-4a17-b941-1a2f1c7cedff":{"name":"HID Crescendo C3000"},"5b0e46ba-db02-44ac-b979-ca9b84f5e335":{"name":"YubiKey 5 FIPS Series with Lightning Preview"},"820d89ed-d65a-409e-85cb-f73f0578f82a":{"name":"IDmelon iOS Authenticator"},"3124e301-f14e-4e38-876d-fbeeb090e7bf":{"name":"YubiKey 5 Series with Lightning Preview"},"b6ede29c-3772-412c-8a78-539c1f4c62d2":{"name":"Feitian BioPass FIDO2 Plus Authenticator"},"85203421-48f9-4355-9bc8-8a53846e5083":{"name":"YubiKey 5 FIPS Series with Lightning"},"d821a7d4-e97c-4cb6-bd82-4237731fd4be":{"name":"Hyper FIDO Bio Security Key"},"9876631b-d4a0-427f-5773-0ec71c9e0279":{"name":"Somu Secp256R1 FIDO2 CTAP2 Authenticator"},"f56f58b3-d711-4afc-ba7d-6ac05f88cb19":{"name":"WinMagic FIDO Eazy - Phone"},"f4c63eff-d26c-4248-801c-3736c7eaa93a":{"name":"FIDO KeyPass S3"},"d384db22-4d50-ebde-2eac-5765cf1e2a44":{"name":"Excelsecu eSecu FIDO2 Fingerprint Security Key"},"b93fd961-f2e6-462f-b122-82002247de78":{"name":"Android Authenticator with SafetyNet Attestation"},"2fc0579f-8113-47ea-b116-bb5a8db9202a":{"name":"YubiKey 5 Series with NFC"},"31c3f7ff-bf15-4327-83ec-9336abcbcd34":{"name":"WinMagic FIDO Eazy - Software"},"9ddd1817-af5a-4672-a2b9-3e3dd95000a9":{"name":"Windows Hello"},"d8522d9f-575b-4866-88a9-ba99fa02f35b":{"name":"YubiKey Bio Series"},"50a45b0c-80e7-f944-bf29-f552bfa2e048":{"name":"ACS FIDO Authenticator"},"f7c558a0-f465-11e8-b568-0800200c9a66":{"name":"KONAI Secp256R1 FIDO2 Conformance Testing CTAP2 Authenticator"},"3f59672f-20aa-4afe-b6f4-7e5e916b6d98":{"name":"Arculus FIDO 2.1 Key Card [P71]"},"42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3":{"name":"Google Titan Security Key v2"},"361a3082-0278-4583-a16f-72a527f973e4":{"name":"eWBM eFA500 FIDO2 Authenticator"},"2ffd6452-01da-471f-821b-ea4bf6c8676a":{"name":"IDPrime 941 Fido"},"30b5035e-d297-4ff7-b00b-addc96ba6a98":{"name":"OneSpan DIGIPASS FX7"},"692db549-7ae5-44d5-a1e5-dd20a493b723":{"name":"HID Crescendo Key"},"bbf4b6a7-679d-f6fc-c4f2-8ac0ddf9015a":{"name":"Excelsecu eSecu FIDO2 PRO Security Key"},"3e22415d-7fdf-4ea4-8a0c-dd60c4249b9d":{"name":"Feitian iePass FIDO Authenticator"},"23786452-f02d-4344-87ed-aaf703726881":{"name":"SafeNet eToken Fusion CC"},"234cd403-35a2-4cc2-8015-77ea280c77f5":{"name":"Feitian ePass FIDO2-NFC Series (CTAP2.1, CTAP2.0, U2F)"},"aeb6569c-f8fb-4950-ac60-24ca2bbe2e52":{"name":"HID Crescendo C2300"},"87dbc5a1-4c94-4dc8-8a47-97d800fd1f3c":{"name":"eWBM eFA320 FIDO2 Authenticator"},"7d2afadd-bf6b-44a2-a66b-e831fceb8eff":{"name":"Taglio CTAP2.1 EP"},"9f0d8150-baa5-4c00-9299-ad62c8bb4e87":{"name":"GoTrust Idem Card FIDO2 Authenticator"},"12ded745-4bed-47d4-abaa-e713f51d6393":{"name":"Feitian AllinOne FIDO2 Authenticator"},"88bbd2f0-342a-42e7-9729-dd158be5407a":{"name":"Precision InnaIT Key FIDO 2 Level 2 certified"},"34f5766d-1536-4a24-9033-0e294e510fb0":{"name":"YubiKey 5 Series with NFC Preview"},"83c47309-aabb-4108-8470-8be838b573cb":{"name":"YubiKey Bio Series (Enterprise Profile)"},"be727034-574a-f799-5c76-0929e0430973":{"name":"Crayonic KeyVault K1 (USB-NFC-BLE FIDO2 Authenticator)"},"092277e5-8437-46b5-b911-ea64b294acb7":{"name":"Taglio CTAP2.1 CS"},"ca87cb70-4c1b-4579-a8e8-4efdd7c007e0":{"name":"FIDO Alliance TruU Sample FIDO2 Authenticator"},"58b44d0b-0a7c-f33a-fd48-f7153c871352":{"name":"Ledger Nano S Plus FIDO2 Authenticator"},"454e5346-4944-4ffd-6c93-8e9267193e9b":{"name":"Ensurity AUTH BioPro"},"e77e3c64-05e3-428b-8824-0cbeb04b829d":{"name":"Security Key NFC by Yubico"},"7d1351a6-e097-4852-b8bf-c9ac5c9ce4a3":{"name":"YubiKey Bio Series - Multi-protocol Edition"},"07a9f89c-6407-4594-9d56-621d5f1e358b":{"name":"NXP Semiconductros FIDO2 Conformance Testing CTAP2 Authenticator"},"d61d3b87-3e7c-4aea-9c50-441c371903ad":{"name":"KeyVault Secp256R1 FIDO2 CTAP2 Authenticator"},"5ca1ab1e-1337-fa57-f1d0-a117e71ca702":{"name":"Allthenticator App: roaming BLE FIDO2 Allthenticator for Windows, Mac, Linux, and Allthenticate door readers"},"b92c3f9a-c014-4056-887f-140a2501163b":{"name":"Security Key by Yubico"},"54d9fee8-e621-4291-8b18-7157b99c5bec":{"name":"HID Crescendo Enabled"},"a25342c0-3cdc-4414-8e46-f4807fca511c":{"name":"YubiKey 5 Series with NFC"},"20f0be98-9af9-986a-4b42-8eca4acb28e4":{"name":"Excelsecu eSecu FIDO2 Fingerprint Security Key"},"ca4cff1b-5a81-4404-8194-59aabcf1660b":{"name":"IDPrime 3930 FIDO"},"ab32f0c6-2239-afbb-c470-d2ef4e254db6":{"name":"TEST (DUMMY RECORD)"},"760eda36-00aa-4d29-855b-4012a182cdeb":{"name":"Security Key NFC by Yubico Preview"},"6028b017-b1d4-4c02-b4b3-afcdafc96bb2":{"name":"Windows Hello"},"30b5035e-d297-4fc1-b00b-addc96ba6a97":{"name":"OneSpan FIDO Touch"},"6d44ba9b-f6ec-2e49-b930-0c8fe920cb73":{"name":"Security Key by Yubico with NFC"},"eabb46cc-e241-80bf-ae9e-96fa6d2975cf":{"name":"TOKEN2 PIN Plus Security Key Series "},"53414d53-554e-4700-0000-000000000000":{"name":"Samsung Pass"},"e416201b-afeb-41ca-a03d-2281c28322aa":{"name":"ATKey.Pro CTAP2.1"},"cfcb13a2-244f-4b36-9077-82b79d6a7de7":{"name":"USB/NFC Passcode Authenticator"},"91ad6b93-264b-4987-8737-3a690cad6917":{"name":"Token Ring FIDO2 Authenticator"},"9f77e279-a6e2-4d58-b700-31e5943c6a98":{"name":"Hyper FIDO Pro"},"0bb43545-fd2c-4185-87dd-feb0b2916ace":{"name":"Security Key NFC by Yubico - Enterprise Edition"},"73402251-f2a8-4f03-873e-3cb6db604b03":{"name":"uTrust FIDO2 Security Key"},"c1f9a0bc-1dd2-404a-b27f-8e29047a43fd":{"name":"YubiKey 5 FIPS Series with NFC"},"504d7149-4e4c-3841-4555-55445a677357":{"name":"WiSECURE AuthTron USB FIDO2 Authenticator"},"a3975549-b191-fd67-b8fb-017e2917fdb3":{"name":"Excelsecu eSecu FIDO2 NFC Security Key"},"19083c3d-8383-4b18-bc03-8f1c9ab2fd1b":{"name":"YubiKey 5 Series"},"da1fa263-8b25-42b6-a820-c0036f21ba7f":{"name":"ATKey.Card NFC"},"6002f033-3c07-ce3e-d0f7-0ffe5ed42543":{"name":"Excelsecu eSecu FIDO2 Fingerprint Key"},"5fdb81b8-53f0-4967-a881-f5ec26fe4d18":{"name":"VinCSS FIDO2 Authenticator"},"2d3bec26-15ee-4f5d-88b2-53622490270b":{"name":"HID Crescendo Key V2"},"30b5035e-d297-4ff1-010b-addc96ba6a98":{"name":"OneSpan DIGIPASS FX1a"},"cb69481e-8ff7-4039-93ec-0a2729a154a8":{"name":"YubiKey 5 Series"},"0076631b-d4a0-427f-5773-0ec71c9e0279":{"name":"HYPR FIDO2 Authenticator"},"d7a423ad-3e19-4492-9200-78137dccc136":{"name":"VivoKey Apex FIDO2"},"ba76a271-6eb6-4171-874d-b6428dbe3437":{"name":"ATKey.ProS"},"ee882879-721c-4913-9775-3dfcce97072a":{"name":"YubiKey 5 Series"},"8876631b-d4a0-427f-5773-0ec71c9e0279":{"name":"Solo Secp256R1 FIDO2 CTAP2 Authenticator"},"fec067a1-f1d0-4c5e-b4c0-cc3237475461":{"name":"KX701 SmartToken FIDO"},"30b5035e-d297-4ff1-b00b-addc96ba6a98":{"name":"OneSpan DIGIPASS FX1 BIO"},"b267239b-954f-4041-a01b-ee4f33c145b6":{"name":"authenton1 - CTAP2.1"},"b50d5e0a-7f81-4959-9b12-f45407407503":{"name":"IDPrime 3940 FIDO"},"8c97a730-3f7b-41a6-87d6-1e9b62bda6f0":{"name":"FT-JCOS FIDO Fingerprint Card"},"99bf4610-ec26-4252-b31f-7380ccd59db5":{"name":"ZTPass Card"},"a1f52be5-dfab-4364-b51c-2bd496b14a56":{"name":"OCTATCO EzFinger2 FIDO2 AUTHENTICATOR"},"ba86dc56-635f-4141-aef6-00227b1b9af6":{"name":"TruU Windows Authenticator"},"3e078ffd-4c54-4586-8baa-a77da113aec5":{"name":"Hideez Key 3 FIDO2"},"ec31b4cc-2acc-4b8e-9c01-bade00ccbe26":{"name":"KeyXentic FIDO2 Secp256R1 FIDO2 CTAP2 Authenticator"},"5d629218-d3a5-11ed-afa1-0242ac120002":{"name":"Swissbit iShield Key Pro"},"d41f5a69-b817-4144-a13c-9ebd6d9254d6":{"name":"ATKey.Card CTAP2.0"},"e86addcd-7711-47e5-b42a-c18257b0bf61":{"name":"IDCore 3121 Fido"},"95442b2e-f15e-4def-b270-efb106facb4e":{"name":"eWBM eFA310 FIDO2 Authenticator"},"cdbdaea2-c415-5073-50f7-c04e968640b6":{"name":"Excelsecu eSecu FIDO2 Security Key"},"bc2fe499-0d8e-4ffe-96f3-94a82840cf8c":{"name":"OCTATCO EzQuant FIDO2 AUTHENTICATOR"},"eb3b131e-59dc-536a-d176-cb7306da10f5":{"name":"ellipticSecure MIRkey USB Authenticator"},"1c086528-58d5-f211-823c-356786e36140":{"name":"Atos CardOS FIDO2"},"77010bd7-212a-4fc9-b236-d2ca5e9d4084":{"name":"Feitian BioPass FIDO2 Authenticator"},"d94a29d9-52dd-4247-9c2d-8b818b610389":{"name":"VeriMark Guard Fingerprint Key"},"833b721a-ff5f-4d00-bb2e-bdda3ec01e29":{"name":"Feitian ePass FIDO2 Authenticator"},"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4":{"name":"Google Password Manager"},"adce0002-35bc-c60a-648b-0b25f1f05503":{"name":"Chrome on Mac"},"dd4ec289-e01d-41c9-bb89-70fa845d4bf2":{"name":"iCloud Keychain (Managed)"},"531126d6-e717-415c-9320-3d9aa6981239":{"name":"Dashlane"},"bada5566-a7aa-401f-bd96-45619a55120d":{"name":"1Password"},"b84e4048-15dc-4dd0-8640-f4f60813c8af":{"name":"NordPass"},"0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6":{"name":"Keeper"},"891494da-2c90-4d31-a9cd-4eab0aed1309":{"name":"Sésame"},"f3809540-7f14-49c1-a8b3-8f813b225541":{"name":"Enpass"},"b5397666-4885-aa6b-cebf-e52262a439a2":{"name":"Chromium Browser"},"771b48fd-d3d4-4f74-9232-fc157ab0507a":{"name":"Edge on Mac"},"d548826e-79b4-db40-a3d8-11116f7e8349":{"name":"Bitwarden"},"fbfc3007-154e-4ecc-8c0b-6e020557d7bd":{"name":"iCloud Keychain"},"66a0ccb3-bd6a-191f-ee06-e375c50b9846":{"name":"Thales Bio iOS SDK"},"8836336a-f590-0921-301d-46427531eee6":{"name":"Thales Bio Android SDK"},"cd69adb5-3c7a-deb9-3177-6800ea6cb72a":{"name":"Thales PIN Android SDK"},"17290f1e-c212-34d0-1423-365d729f09d9":{"name":"Thales PIN iOS SDK"},"50726f74-6f6e-5061-7373-50726f746f6e":{"name":"Proton Pass"},"fdb141b2-5d84-443e-8a35-4698c205a502":{"name":"KeePassXC"},"cc45f64e-52a2-451b-831a-4edd8022a202":{"name":"ToothPic Passkey Provider"}};

function generatePasskeyNickname() {
    let fidoNickname = "";

    // perform a dirty client-side read (before server-side validation) of the registration data
    // to extract the AAGUID and see if we can derive some authenticator provider information
    // from our known list of AAGUIDS.
    let aaguid = null;
    let flags = 0;
    try {
        let attestationObjectBytes = b64toBA(b64utob64(enrollCredInfo.response.attestationObject));
        let decodedAttestationObject = CBOR.decode((new Uint8Array(attestationObjectBytes)).buffer);
        console.log("decodedAttestationObject: " + JSON.stringify(decodedAttestationObject));
        let unpackedAuthData = unpackAuthData(bytesFromArray(decodedAttestationObject.authData, 0, -1));
        if (unpackedAuthData["status"]) {
            aaguid = aaguidBytesToUUID(unpackedAuthData.attestedCredData.aaguid).toLowerCase();
            flags = unpackedAuthData.flags;
            console.log("The aaguid is: " + aaguid);
        }
    } catch (e) {
        console.log("Error unpacking attestationObject: " + e);
    }

    if (aaguid != null) {
        let candidate = aaguidLookupTable[aaguid];
        if (candidate != null && candidate.name != null) {
            fidoNickname = candidate.name + "-" + (new Date()).toUTCString();
        }
    } 

    if (fidoNickname == "") {
        fidoNickname = "MyPasskey-" + (new Date()).toUTCString();
    }

    // also check if it is claimed to be a synced passkey and add this to the name if it is
    if (flags & 0x10) {
        fidoNickname += '  (synced)';
    }

    return fidoNickname;
}

function determineAuthenticatorAttachment() {
    performWebAuthnFeatureDiscovery().then(() => {
        // isUVPAA should now be set
        if (isUVPAA) {
            console.log("isUVPAA is true, soliciting platform authenticator registration");
            attestationOptions.authenticatorSelection.authenticatorAttachment = "platform";
            document.getElementById("enrollmentHeadingDiv").innerText = "Add a platform passkey";
            document.getElementById("instructionsTextDiv").innerText = "Use your device unlock mechanism to authenticate on the web.";
        } else {
            console.log("isUVPAA is false, soliciting any passkey registration");
            document.getElementById("enrollmentHeadingDiv").innerText = "Add a passkey";
            document.getElementById("instructionsTextDiv").innerText = "Use your device unlock mechanism, a mobile device, or a hardware security key to authenticate on the web.";
        }

        // now auto-start the registration process!
        document.getElementById("register-button").click();
    });
}


// similar to the testFidoDevice function from fido2_register.js, but designed to be re-entrant on a failure
// by detecting if data type conversions have already been performed and hiding the error at the start
function solicitedPasskeyRegisterDevice() {
    const elOne = document.getElementById('customErrorDiv');
    const elTwo = document.getElementById('abortlinkdiv');
    elementsToHide([elOne, elTwo]);

    document.getElementById("register-button").disabled = true; 
    var response = attestationOptions;
    if (!(response.user.id instanceof Uint8Array)) {
        response.user.id = new Uint8Array(b64toBA(b64utob64(response.user.id)));
    }

    if (!(response.challenge instanceof Uint8Array)) {
        response.challenge = new Uint8Array(b64toBA(b64utob64(response.challenge)));
    }

    if (response.excludeCredentials !== null && response.excludeCredentials.length > 0) {
        for (var credential of response.excludeCredentials) {
        if (!(credential.id instanceof Uint8Array)) {
            var b64uCID = credential.id;
            credential.id = new Uint8Array(b64toBA(b64utob64(b64uCID)));
        }
        }
    }

    let credCreateOptions = {
        publicKey: response
    };
    console.log("solicitedPasskeyRegisterDevice: calling navigator.credentials.create with options: " + JSON.stringify(credCreateOptions));

    navigator.credentials.create(credCreateOptions)
        .then(mySuccess)
        .catch(myFailedStepup);
}

function mySuccess(credInfo) {
    enrollCredInfo = {
       enabled: true,
       id: credInfo.id,
       rawId: credInfo.id,
       response: {
          attestationObject: hextob64u(BAtohex(new Uint8Array(credInfo.response.attestationObject))),
          clientDataJSON: hextob64u(BAtohex(new Uint8Array(credInfo.response.clientDataJSON)))
       },
       type: credInfo.type
    };

    // add authenticatorAttachment if avaialble
    try {
          if (credInfo.authenticatorAttachment !== undefined && credInfo.authenticatorAttachment != null) {
              enrollCredInfo.authenticatorAttachment = credInfo.authenticatorAttachment; // This will either be "platform" or "cross-platform"
          }
      } catch(err) {
      // ignore errors
    }

    // add getTransports if avaialble
    try {
      if (credInfo.response.getTransports !== undefined && credInfo.response.getTransports() != null) {
              enrollCredInfo.getTransports = credInfo.response.getTransports(); 
          }
        } catch(err) {
      // ignore errors
    }

    // Hide the prepare instructions
    var prepare = document.getElementById("prepare");
    if (prepare != null || prepare != undefined) {
       prepare.classList.add('hidden');
    }
    document.getElementById("instructions").classList.add('hidden');

    // pre-populate the nickname value
    document.getElementById('nickname').value = generatePasskeyNickname();

    // Show the nickname input
    var nameInput = document.getElementById("name-input");
    if (nameInput != null || nameInput != undefined) {
       nameInput.classList.add('block');
    }
    
    // show it
    document.getElementById("enroll").classList.add('block');
}

//
// relabel the button for trying again
// and displays the error text, and shows an abort link
//
function myFailedStepup(er) {
    document.getElementById('register-button').innerText = "Retry passkey registration";

    // taken from the original failedStepup
    console.log("failed in attestation.");
    console.log(er);
    document.getElementById("errorMsg").innerText = "A registration error has occurred";
    document.getElementById("errorMsgDetails").innerText = er.message ? er.message : "";
    document.getElementById("register-button").disabled = false;

    // now show the error and abort link
    document.getElementById('customErrorDiv').classList.add('block');
    document.getElementById('abortlinkdiv').classList.add('block');
}

//
// used to submit the final registration response to the server
//
function registerFidoDevice(event) {
    event.preventDefault();
    var nickname = document.getElementById("nickname").value;
    if (nickname.trim().length === 0) {
        document.getElementById("cs-error-message").innerText = tagJsonFido2Enrollment.nicknameError;
        return false;
    } else {
        document.getElementById("cs-error-message").innerText = "";
    }
    document.getElementById("verify-button").disabled = true;
    enrollCredInfo.nickname = nickname;
    let payload = JSON.stringify(enrollCredInfo);
    console.log(payload);
    document.getElementById("register").attestationResponse.value = payload;
    document.getElementById("register").submit();
}          


function onLoadFido2Enrollment(scriptElement) {
    commonOnLoad(scriptElement);
    let tagJson = JSON.parse(scriptElement.textContent);
    tagJsonFido2Enrollment = tagJson;
    attestationOptions = tagJson.attestationOptions;
    let errorMessage = tagJson.errorMessage;
    let showUseAnotherMethod = tagJson.showUseAnotherMethod;
    
    /************************** Passkey enrolement customization ***********************/
    // Added for platform passkey enrolment

    attestationOptions.authenticatorSelection.residentKey = "required";

    // remove the excludeCredentials list, and allow overwrite of the platform authenticator registration
    // this reduces error conditions that really shouldn't affect the user.
    // If the platform authenticator was already enrolled, this will just mean the local
    // credential is overwritten.
    attestationOptions.excludeCredentials = [];

    /************************************************************************************/


    let registerButton = document.getElementById("register-button");
    if (registerButton != null) {
        registerButton.addEventListener('click', solicitedPasskeyRegisterDevice);
    }

    let abortPasskeyRegistrationHref = document.getElementById("abortPasskeyRegistrationHref");
    if (abortPasskeyRegistrationHref != null) {
        abortPasskeyRegistrationHref.href = "javascript:void(0)";
        abortPasskeyRegistrationHref.addEventListener('click', abortPasskeyRegistration);
    }

    let verifyButton = document.getElementById("verify-button");
    if (verifyButton != null) {
        verifyButton.addEventListener('click', registerFidoDevice);
    }

    determineAuthenticatorAttachment();
}

/***************************
 * Used by enrollment_selection.html
***************************/

function onLoadEnrollmentSelection(scriptElement) {
    commonOnLoad(scriptElement);
    document.getElementById("mfa_registration").submit();
}

/***************************
 * Used by passwordless_fido2.html
***************************/

var serverOptions;
var assertionResponseObject;

function onLoadPasswordlessFido2(scriptElement) {
    commonOnLoad(scriptElement);
    let tagJson = JSON.parse(scriptElement.textContent);

    let isEnrollment = tagJson.isEnrollment;
    serverOptions = tagJson.serverOptions;
    let showUseAnotherMethod = tagJson.showUseAnotherMethod;

    //
    // For this theme all credentials should be platform. We improve the  UX by explicitly annotating that 
    // the credential being verified supports only the "internal" transport.  What this does, for example, 
    // is encourage the browser to not expose the QR for cross-domain (hybrid) or USB transports 
    // (e.g. hardware security key won't blink) because they can never be the way the platform credential is located.
    //
    // In future this shouldn't be needed when the ISV platform stores transports for a credential at registration time.
    //
    if (isEnrollment == "true" && serverOptions.allowCredentials != null && serverOptions.allowCredentials.length > 0) {
        serverOptions.allowCredentials.forEach((x) => x.transports = ["internal"]);
    }
    //console.log("serverOptions: " + JSON.stringify(serverOptions));

    // only show the use another method option when appropriate - which is when
    // 2fa is required. There is no point in showing "use another method" when 
    // performing the verification of the credential during the registration ceremony
    // since the "only thing" you can be doing is verifying the just-registered credential.
    if (isEnrollment != "true" && showUseAnotherMethod == "true") {
        document.getElementById('abortSection').classList.add('block');
    }

    //
    // add click handler for goBack href
    //
    let goBackHref = document.getElementById("goBackHref");
    if (goBackHref != null) {
        goBackHref.href = "javascript:void(0)";
        goBackHref.addEventListener('click', goBack);
    }
}

/***************************
 * Used by combined_mga_selection.html
***************************/

function cmsGetMethodActionLabel(otpActionLabelObj, methodType) {
    return otpActionLabelObj[methodType] || methodType;
}

function cmsGetMethodTypeLabel(otpTypeLabelObj, methodType) {
    return otpTypeLabelObj[methodType] || methodType;
}

function cmsSubmit(e) {
    e.preventDefault()
    e.stopPropagation()
    document.getElementById("delivery-selection-input").value = e.currentTarget.idParam
    document.getElementById("combined-form").submit()
}

function closeHelpModal(e){
    e.preventDefault()
    document.getElementById('help-modal-container').classList.remove('is-visible')
}
function openHelpModal(e){
    e.preventDefault()
    document.getElementById('help-modal-container').classList.add('is-visible')
}

function onLoadCombinedMfaSelection(scriptElement) {
    commonOnLoad(scriptElement);
    // the replace here gets rid of the trailing comma in the last object in the array of methods
    let tagJson = JSON.parse(scriptElement.textContent.replace(/},\s*]/,"}]"));

    // annotate each of the methods objects with its derived type
    if (tagJson.methods != null && tagJson.methods.length > 0) {
        for (let i = 0; i < tagJson.methods.length; i++) {
            tagJson.methods[i]["methodType"] = tagJson.methods[i]["methodId"].split('_')[0];
        }
    }

    let methods = tagJson.methods;

    let abortPasskeyRegistrationHref = document.getElementById("abortPasskeyRegistrationHref");
    if (abortPasskeyRegistrationHref != null) {
        abortPasskeyRegistrationHref.href = "javascript:void(0)";
        abortPasskeyRegistrationHref.addEventListener('click', abortPasskeyRegistration);
    }

    let openHelpModalHref = document.getElementById("openHelpModalHref");
    if (openHelpModalHref != null) {
        openHelpModalHref.href = "#";
        openHelpModalHref.addEventListener('click', openHelpModal);
    }

    let closeHelpModalButton = document.getElementById("closeHelpModalButton");
    if (closeHelpModalButton != null) {
        closeHelpModalButton.addEventListener('click', closeHelpModal);
    }

    //
    // this is taken from combinedmfa_selection.js since we removed it from the page
    //
    let otpTypeLabelObj = {
        email: tagJson.otpTypeEmail,
        sms: tagJson.otpTypeSMS,
        verify: tagJson.otpTypeVerify,
        totp: tagJson.otpTypeTotp,
        kq: tagJson.otpTypeKQ,
        fido2: tagJson.otpTypeFido2
    };

    // to make sure backward compatibility
    if (typeof tagJson.otpTypeVoiceOTP !== 'undefined') {
        otpTypeLabelObj['voiceotp'] = tagJson.otpTypeVoiceOTP;
    }

    
    let otpActionLabelObj = {
        email: tagJson.otpActionEmail,
        sms: tagJson.otpActionSMS,
        verify: tagJson.otpActionVerfiy,
        totp: tagJson.otpActionTotp,
        kq: tagJson.otpActionKQ,
        fido2: tagJson.otpActionFido2,
        smsotp: tagJson.otpActionSMS,
        hotp: tagJson.otpActionTotp,
        push: tagJson.otpActionVerfiy,
        emailotp: tagJson.otpActionEmail
    };

    // to make sure backward compatibility
    if (typeof tagJson.otpActionVoiceOTP !== 'undefined') {
        otpActionLabelObj['voiceotp'] = tagJson.otpActionVoiceOTP;
    }
    
    
    /**
     * Build an object (methodMap) that has all groups of methods by type, and each method for each group that's available
     * Interface:
     * {
     * 	[methodType: string]: {
     * 		methodTypeLabel: string;
     * 		methods: {
     * 			methodLabel: string;
     * 			methodActionLabel: string;
     * 			methodId: string;
     * 		}[];
     * 	}
     * }
     */
    var methodMap = {}
    var i
    for (i=0; i<methods.length; i++) {
        var methodType;
        var groupLabel;
        var capability;
        if (methods[i].methodType == "mfaprovider") {
            methodType = methods[i].groupId;
            groupLabel = methods[i].groupLabel;
            capability = methods[i].capability;
        } else {
            methodType = methods[i].methodType;
            groupLabel = cmsGetMethodTypeLabel(otpTypeLabelObj, methods[i].methodType);
            capability = methods[i].methodType;
        }
        if (Object.keys(methodMap).indexOf(methodType) === -1) {
            methodMap[methodType] = {
                methodTypeLabel: groupLabel,
                methods: [{
                    methodLabel: methods[i].methodLabel,
                    methodActionLabel: cmsGetMethodActionLabel(otpActionLabelObj, capability),
                    methodId: methods[i].methodId
                }]
            }
        } else {
            methodMap[methodType].methods.push({
                methodLabel: methods[i].methodLabel,
                methodActionLabel: cmsGetMethodActionLabel(otpActionLabelObj, capability),
                methodId: methods[i].methodId
            })
        }
    }
    //Generate OTP Methods HTML
    //for each method type (email, sms, push, etc)
    var methodContainers = document.getElementById('method-containers')
    Object.keys(methodMap).forEach(function (methodType) {
        var methodContainer = document.createElement('div')
        methodContainer.classList.add('method-container')
        methodContainers.appendChild(methodContainer)
        var node = document.createElement('h6')
        var textNode = document.createTextNode(methodMap[methodType].methodTypeLabel)
        node.appendChild(textNode)
    
        if (methodType != 'kq') {
            methodContainer.appendChild(node)
        }
        node = document.createElement('ul')
        node.classList.add('method-list')
        methodContainer.appendChild(node)
        //for each method of this type (push device 1, push device 2, etc)
        var i
        var currentMethods = methodMap[methodType].methods
        for (i=0; i<currentMethods.length; i++){
            var liNode = document.createElement('li')
            liNode.classList.add('method-item')
            node.appendChild(liNode)
            var methodNameNode
            if (methodType == 'kq'){
                methodNameNode = document.createElement('h6')
            } else {
                methodNameNode = document.createElement('div')
            }
            var methodActionNode = document.createElement('a')
            methodNameNode.classList.add('method-name')
            methodActionNode.classList.add('method-action')
            var att = document.createAttribute('href')
            att.value = '#'
            methodActionNode.setAttributeNode(att)
            att = document.createAttribute('data-ci-key')
            att.value = currentMethods[i].methodId
            methodActionNode.setAttributeNode(att)
            methodActionNode.addEventListener('click', cmsSubmit, false);
            methodActionNode.idParam = currentMethods[i].methodId;
            if (methodType == 'kq'){
                textNode = document.createTextNode(methodMap[methodType].methodTypeLabel)
            } else {
                textNode = document.createTextNode(currentMethods[i].methodLabel)
            }
            methodNameNode.appendChild(textNode)
            textNode = document.createTextNode(currentMethods[i].methodActionLabel)
            methodActionNode.appendChild(textNode)
            liNode.appendChild(methodNameNode)
            liNode.appendChild(methodActionNode)
        }
    });
    
    document.getElementById("combined-form").action = buildTemplateFormAction("", tagJson.action, tagJson.themeId)
    
    //clear countdown(OTP timer) session storage
    sessionStorage.removeItem('timeRemaining')
    sessionStorage.removeItem('navigationTime')    
}

/***************************
 * Used by forgot_password_success.html
***************************/

function solicitPasskey() {
    window.location.replace("/flows/?reference=passkeyregistration&themeId="+passkeyregThemeId+"&Target=/usc");
}

function onLoadForgotPasswordSuccess(scriptElement) {
    commonOnLoad(scriptElement);
    let tagJson = JSON.parse(scriptElement.textContent);

    let passkeyHref = document.getElementById("passkeyHref");
    if (passkeyHref != null) {
        passkeyHref.href = "javascript:void(0)";
        passkeyHref.addEventListener('click', solicitPasskey);
    }

    //
    // because this page is used for multiple steps (including when sending out the reset link)
    // we only show the passkey registration button when password reset was actually complete
    // we detect this by the message id being displayed
    //
    if (tagJson.message.indexOf("CSIAH0324I") >= 0) {
        performWebAuthnFeatureDiscovery().then(() => {
            if (isUVPAA) {
                showDiv("passkeyInstructionDiv");
                showDiv("passkeyButtonDiv");
            }
        });
    }
}

/***************************
 * Used by combined_login_selection.html
***************************/

function onLoadCombinedLoginSelection(scriptElement) {
    commonOnLoad(scriptElement);
    let tagJson = JSON.parse(scriptElement.textContent);

    let workflowReference = "passkeyregistration";

    // check query string URL for workflowLaunched=true
    // if its there, show regular login, otherwise redirect to workflow
    const urlParams = new URLSearchParams(window.location.search);
    const workflowLaunched = urlParams.get("workflowLaunched");
    if (workflowLaunched == "true") {
        document.getElementById("bodyWrapperDiv").classList.add('block');
    } else {
        window.location.replace("/flows/?reference=" + workflowReference + "&themeId=" + passkeyregThemeId)
    }
}

/***************************
 * Main entry point
***************************/

window.addEventListener("load", () => {
    let customPage1ScriptElement = document.getElementById('custom-page1-script');
    let customPage2ScriptElement = document.getElementById('custom-page2-script');
    let customPage3ScriptElement = document.getElementById('custom-page3-script');
    let customPage4ScriptElement = document.getElementById('custom-page4-script');

    let enrollmentSuccessScriptElement = document.getElementById('enrollment-success-script');
    let fido2EnrollmentScriptElement = document.getElementById('fido2-enrollment-script');
    let enrollmentSelectionScriptElement = document.getElementById('enrollment-selection-script');
    let passwordlessFido2ScriptElement = document.getElementById('passwordless-fido2-script');
    let combinedMfaSelectionScriptElement = document.getElementById('combined-mfa-selection-script');
    
    let forgotPasswordSuccessScriptElement = document.getElementById('forgot-password-success-script');
    let combinedLoginSelectionScriptElement = document.getElementById('combined-login-selection-script');

    if (combinedLoginSelectionScriptElement != null) {
        // onload function for combined_login_selection.html
        onLoadCombinedLoginSelection(combinedLoginSelectionScriptElement);
    } else if (customPage1ScriptElement != null) {
        // onload function for custom_page1.html
        onLoadCustomPage1(customPage1ScriptElement);
    } else if (customPage2ScriptElement != null) {
        // onload function for custom_page2.html
        onLoadCustomPage2(customPage2ScriptElement);
    } else if (customPage3ScriptElement != null) {
        // onload function for custom_page3.html
        onLoadCustomPage3(customPage3ScriptElement);
    } else if (customPage4ScriptElement != null) {
        // onload function for custom_page4.html
        onLoadCustomPage4(customPage4ScriptElement);
    } else if (enrollmentSuccessScriptElement != null) {
        // onload function for enrollment_success.html
        onLoadEnrollmentSuccess(enrollmentSuccessScriptElement);
    } else if (fido2EnrollmentScriptElement != null) {
        // onload function for fido2_enrollment.html
        onLoadFido2Enrollment(fido2EnrollmentScriptElement);
    } else if (enrollmentSelectionScriptElement != null) {
        // onload function for enrollment_selection.html
        onLoadEnrollmentSelection(enrollmentSelectionScriptElement);
    } else if (passwordlessFido2ScriptElement != null) {
        // onload function for passwordless_fido2.html
        onLoadPasswordlessFido2(passwordlessFido2ScriptElement);
    } else if (combinedMfaSelectionScriptElement != null) {
        // onload function for combined_mfa_selection.html
        onLoadCombinedMfaSelection(combinedMfaSelectionScriptElement);
    } else if (forgotPasswordSuccessScriptElement != null) {
        // onload function for forgot_password_success.html
        onLoadForgotPasswordSuccess(forgotPasswordSuccessScriptElement);
    }
});

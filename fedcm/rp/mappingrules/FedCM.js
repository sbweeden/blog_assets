importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.fedmgr2.trust.util.LocalSTSClient);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.STSUniversalUser);
importClass(Packages.com.tivoli.am.fim.base64.BASE64Utility);

/*
* This contains the configuration properties for the IDP to be used
*
* At least in Chrome 125, if you have multiple entries in the IDP configuration list, 
* then you also need to enable the chrome flag: chrome://flags/#fedcm-multi-idp
*
* Settings for Google as an IDP can be configured using the Google APIs console: https://console.cloud.google.com/apis
* More information at: https://developers.google.com/identity/gsi/web/guides/get-google-api-clientid
* Be sure to add your RP web origin to the Authorized JavaScript origins of the credentials for your web application client
*/
const _idpConfiguration = {
	"https://fidointerop.securitypoc.com": {
		clientID: "1e8697b0-2791-11ef-b4dd-bff0b72b7f0d",
		clientConfigURL: "https://fidointerop.securitypoc.com/fedcm/config.json",
		jwksEndpoint: "https://fidointerop.securitypoc.com/jwks"
	}
	/*
	,
	"https://accounts.google.com": {
		clientID: "296002639042.apps.googleusercontent.com",
		clientConfigURL: "https://accounts.google.com/gsi/fedcm.json",
		jwksEndpoint: "https://www.googleapis.com/oauth2/v3/certs"		
	}
	*/
};







page.setValue("/authsvc/authenticator/fedcm/fedcmrp.html");

var result = false;
var fedcmState = {
	idpConfig: _idpConfiguration
};


function encode_utf8(s) {
	return unescape(encodeURIComponent(s));
}

function decode_utf8(s) {
	return decodeURIComponent(escape(s));
}

function javascriptStringToJavaString(s) {
	return new java.lang.String(s);
}

function byteArrayToJavaString(b,e) {
	return new java.lang.String(b,e);
}

/**
 * base64url encode/decode https://www.rfc-editor.org/rfc/rfc7515.txt
 */
function base64urlencode(s) {
	var sbytes = javascriptStringToJavaString(encode_utf8(s)).getBytes("UTF-8");
	var b64txt = BASE64Utility.encode(sbytes, false);
	var result = b64txt.split("=")[0].replace(/\+/g,"-").replace(/\//g,"_");
	//IDMappingExtUtils.traceString("base64urlencode s: " + s + " result: " + result);
	return result;
}

/**
 * base64url encode/decode https://www.rfc-editor.org/rfc/rfc7515.txt
 */
function base64urldecode(s) {
	let s2 = s.replace(/-/g,"+").replace(/_/g,"/");
	switch (s2.length % 4) {
		case 0: break;
		case 2: s2 += "=="; break;
		case 3: s2 += "="; break;
		default: throw "Illegal base64 string";
	}
	let result = decode_utf8(byteArrayToJavaString(BASE64Utility.decode(s2),"UTF-8"));
	//IDMappingExtUtils.traceString("base64urldecode s: " + s + " result: " + result);
	return result;
}

function getClaims(jwt) {
	let result = null;
	if (jwt != null) {
		let jwtArray = jwt.split(".");
		if (jwtArray != null && jwtArray.length == 3) {
			result = JSON.parse(base64urldecode(jwtArray[1]));
		}
	}
	return result;
}

function getIssuer(jwt) {
	let result = null;
	let claims = getClaims(jwt);
	//IDMappingExtUtils.traceString("Claims: " + (claims == null ? "null" : JSON.stringify(claims)));
	if (claims != null) {
		result = claims.iss;
	}
	return result;
}


function generateRandom(len) {
    // generates a random string of alpha-numerics
    var chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    var result = "";
    for (var i = 0; i < len; i++) {
            result = result + chars.charAt(Math.floor(Math.random()*chars.length));
    }
    return result;
}

function doFedCMLogin(t, n) {
	let res = false;
	
	// make sure we know the issuer
	let iss = getIssuer(t);	
	if (iss != null && Object.keys(_idpConfiguration).indexOf(iss) >= 0) {
		// validate this JWT with STS
		let jwtXMLStr = "<wss:BinarySecurityToken "
			+ " xmlns:wss=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\""
			+ " wss:EncodingType=\"http://ibm.com/2004/01/itfim/base64encode\""
			+ " wss:ValueType=\"urn:com:ibm:JWT\">"
			+ t
			+ "</wss:BinarySecurityToken>";
		let jwtXML = IDMappingExtUtils.stringToXMLElement(jwtXMLStr);
		
		
		let wstClaimsStr = "<wst:Claims xmlns:wst=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">"
		+ "<signing.jwksUri>" + _idpConfiguration[iss].jwksEndpoint + "</signing.jwksUri>"
		+ "</wst:Claims>"
	
		let claimsXML = IDMappingExtUtils.stringToXMLElement(wstClaimsStr);
	
	 	// Validate the token using the chain
	  	let wstResult = LocalSTSClient.doRequest("http://schemas.xmlsoap.org/ws/2005/02/trust/Validate", "http://appliesto/stsuu","http://issuer/jwt", jwtXML, claimsXML)
	  	if (wstResult.errorMessage == null) {
			let stsuu = new STSUniversalUser();
			stsuu.fromXML(wstResult.token);
			IDMappingExtUtils.traceString("STS returned stsuu from FedCM JWT validation: " + stsuu.toString());
			
			
			// validate nonce
			fedCMNonce = ''+state.get("FEDCM_NONCE");
			let jwtNonce = stsuu.getAttributeValueByName("nonce");
			if (jwtNonce != null && jwtNonce.equals(fedCMNonce)) {
				// login as this user
				context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", stsuu.getAttributeValueByName("sub"));
				context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "AUTHENTICATION_LEVEL", "2");
				let optionalAttrs = [ "displayName", "email" ];
				optionalAttrs.forEach((a) => {
					let aValue = stsuu.getAttributeValueByName(a);
					if (aValue != null) {
						context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", a, aValue);		
					}
				});
				// worked!
				res = true;
			} else {
				fedcmState.errorMessage = 'JWT nonce mismatch';
			}		
		} else {
			fedcmState.errorMessage = wstResult.errorMessage;
		}
	}
  
 	return res;
}

/*********************************************************************/
/* MAIN LOGIC STARTS HERE */
/*********************************************************************/

// is the fedcm token in this request?
let fedcmToken = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "token");

if (fedcmToken != null) {
	// retrieve the nonce from state
	let nonce = state.get("FEDCM_NONCE");
	if (nonce != null) {
		nonce = ''+nonce;
	}
	
	// try validating the token
	result = doFedCMLogin(''+fedcmToken, nonce);
} 

if (!result) {
	// generate a new nonce which will be stored in state and returned with the login page
	fedcmState.nonce = generateRandom(20);
	state.put("FEDCM_NONCE", fedcmState.nonce);
}

macros.put("@FEDCM_STATE@", JSON.stringify(fedcmState));

success.setValue(result);

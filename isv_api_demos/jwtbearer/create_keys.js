// create_keys.js

//
// Generates an ECDSA keypair for the isv_jwt_bearer.js application to use for performing JWT bearer grant type flows.
//
// Note that a certificate is also generated, but this is solely so that the JWKS can be hosted by an ISV tenant based 
// using the signer certs keystore and the /oauth2/public-jwks endpoint.
//

// get configuration in place
require('dotenv').config();

const fs = require('fs');
const jsrsasign = require('jsrsasign');

let JWTBEARER_DN="/C=US/O=IBM/CN=JWT-BEARER";
let JWTBEARER_PRIVATE_KEY="jwtbearerPrivate.pem";
let JWTBEARER_PUBLIC_KEY="jwtbearerPublic.pem";
let JWTBEARER_CERT="jwtbearerCert.pem";
let JWTBEARER_PRIVATE_KEY_KID="jwtbearer";


/**
 * Converts the bytes of an asn1-encoded X509 ceritificate or raw public key
 * into a PEM-encoded cert string
 */
function certToPEM(cert) {
	let keyType = "CERTIFICATE";
	asn1key = cert;

	if (cert != null && cert.length == 65 && cert[0] == 0x04) {
		// this is a raw public key - prefix with ASN1 metadata
		// SEQUENCE {
		// SEQUENCE {
		// OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
		// OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
		// }
		// BITSTRING <raw public key>
		// }
		// We just need to prefix it with constant 26 bytes of metadata
		asn1key = jsrsasign.b64toBA(
			jsrsasign.hextob64("3059301306072a8648ce3d020106082a8648ce3d030107034200")
		);
		Array.prototype.push.apply(asn1key, cert);
		keyType = "PUBLIC KEY";
	}
	let result = "-----BEGIN " + keyType + "-----\n";
	let b64cert = jsrsasign.hextob64(jsrsasign.BAtohex(asn1key));
	for (; b64cert.length > 64; b64cert = b64cert.slice(64)) {
		result += b64cert.slice(0, 64) + "\n";
	}
	if (b64cert.length > 0) {
		result += b64cert + "\n";
	}
	result += "-----END " + keyType + "-----\n";
	return result;
}

/**
 * Generates  random serial number
 * @returns a serial number
 */
function generateRandomSerialNumberHex() {
    // random bytes, but lets at least make sure its not negative by making sure the left-most bit is 0
    let randHex = jsrsasign.KJUR.crypto.Util.getRandomHexOfNbytes(16);
    let randBytes = jsrsasign.b64toBA(jsrsasign.hextob64(randHex));
    randBytes[0] &= 0x7F;
    return jsrsasign.BAtohex(randBytes);
}

/**
 * Pads a number string with leading zeros up to a given size
 */
function pad(num, size) {
    num = num.toString();
    while (num.length < size) num = "0" + num;
    return num;
}

/**
 * Returns asn.1 GeneralizedTime from a Javascript Date
 * @param {*} d a Javascript Date
 * @returns 
 */
function dateToASN1GeneralizedTime(d) {
    return (pad(d.getUTCFullYear(),2) + pad(d.getUTCMonth()+1,2) + pad(d.getUTCDate(),2) + pad(d.getUTCHours(), 2) + pad(d.getUTCMinutes(),2) + pad(d.getUTCSeconds(),2) + 'Z');
}


/**
 * Main logic starts here
 */

let jwtbearerPublicKeyPEM = null;
let jwtbearerPrivateKeyPEM = null;
if (!fs.existsSync(JWTBEARER_PRIVATE_KEY)) {
    console.log("Creating private key: " + JWTBEARER_PRIVATE_KEY);
    let kp = jsrsasign.KEYUTIL.generateKeypair("EC", "secp256r1");
    jwtbearerPrivateKeyPEM  = jsrsasign.KEYUTIL.getPEM(kp.prvKeyObj, "PKCS8PRV");
    console.log("Creating jwtbearer private key file: " + JWTBEARER_PRIVATE_KEY);
    fs.writeFileSync(JWTBEARER_PRIVATE_KEY, jwtbearerPrivateKeyPEM);
    jwtbearerPublicKeyPEM  = jsrsasign.KEYUTIL.getPEM(kp.pubKeyObj, "PKCS8PUB");
    console.log("Creating jwtbearer public key file: " + JWTBEARER_PUBLIC_KEY);
    fs.writeFileSync(JWTBEARER_PUBLIC_KEY, jwtbearerPublicKeyPEM);
} else {
    // read in existing private key PEM from file and extract public key and convert to PEM
    jwtbearerPrivateKeyPEM = fs.readFileSync(JWTBEARER_PRIVATE_KEY).toString();
    let prvKey = jsrsasign.KEYUTIL.getKey(jwtbearerPrivateKeyPEM);
    jwtbearerPublicKeyPEM = certToPEM(jsrsasign.b64toBA(jsrsasign.hextob64(prvKey.pubKeyHex)));
}
//console.log('jwtbearerPublicKeyPEM: ' + jwtbearerPublicKeyPEM);
//console.log('jwtbearerPrivateKeyPEM: ' + jwtbearerPrivateKeyPEM);

let jwtbearerCertificatePEM = null;
if (!fs.existsSync(JWTBEARER_CERT)) {
    console.log("Creating jwtbearer certificate: " + JWTBEARER_CERT);

    let notBeforeDate = new Date();
    let notAfterDate = new Date();
    // same as -days 9999 for openssl
    notAfterDate.setDate(notAfterDate.getDate() + 9999);

    let cert = new jsrsasign.asn1.x509.Certificate({
        version: 3,
        serial: {hex: generateRandomSerialNumberHex()},
        subject: {str: JWTBEARER_DN},
        issuer: {str: JWTBEARER_DN},
        notbefore: { type: 'gen', str: dateToASN1GeneralizedTime(notBeforeDate) },
        notafter: { type: 'gen', str: dateToASN1GeneralizedTime(notAfterDate) },
        sbjpubkey: jwtbearerPublicKeyPEM,
        ext: [
            {extname: "basicConstraints", cA: true, critical: true},
            {extname: "subjectKeyIdentifier", kid: jwtbearerPublicKeyPEM},
            {extname: "authorityKeyIdentifier", kid: jwtbearerPublicKeyPEM}
        ],
        sigalg: "SHA256withECDSA",
        cakey: jwtbearerPrivateKeyPEM
    });

    jwtbearerCertificatePEM = cert.getPEM();
    fs.writeFileSync(JWTBEARER_CERT, jwtbearerCertificatePEM);
} else {
    jwtbearerCertificatePEM = fs.readFileSync(JWTBEARER_CERT).toString();
}
//console.log('jwtbearerCertificatePEM: ' + jwtbearerCertificatePEM);

console.log("The JWK entry for the public key should be:");
let pubKey = jsrsasign.KEYUTIL.getKey(jwtbearerPublicKeyPEM);
let jwkObj = jsrsasign.KEYUTIL.getJWKFromKey(pubKey);
// this is is one way to generate a kid, but in our case we're going to use a static string
//jwkObj.kid = jsrsasign.KJUR.jws.JWS.getJWKthumbprint(jwkObj);
jwkObj.kid = JWTBEARER_PRIVATE_KEY_KID;
jwkObj.use = "sig";
console.log(JSON.stringify(jwkObj));

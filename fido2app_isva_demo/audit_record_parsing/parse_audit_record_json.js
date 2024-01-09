// relies on fidotools.js from postman collection

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

/*
* returns true if o's keys are only "0", "1", ... "n"
*/
function integerKeys(o) {
	var result = false;
	if (o != null) {
		var oKeys = Object.keys(o);
		var intArray = [...Array(oKeys.length).keys()];
		var result = true;
		for (var i = 0; i < intArray.length && result; i++) {
			if (oKeys[i] != ''+intArray[i]) {
				result = false;
			}
		}
	}
	return result;
}

/*
* Recursively inspect every element of o and if it is an object which is not already 
* an Array and who's keys are only the numbers from 0...x then assume that object is an
* ArrayBuffer and convert to BA.
*/
function convertArrayBuffersToByteArrays(o) {
	if (o != null) {
		Object.keys(o).forEach((k)=> {
			if (typeof o[k] == "object") {
				if (!Array.isArray(o[k]) && integerKeys(o[k])) {
					o[k] = bytesFromArray(o[k], 0, -1);
				} else {
					convertArrayBuffersToByteArrays(o[k]);
				}
			}
		});
	}
	return o;
}

function credentialPublicKeyStringToCOSEKey(s) {
	return convertArrayBuffersToByteArrays(CBOR.decode(new Uint8Array(b64toBA(b64utob64(s))).buffer));
}

function hackExtensions(e) {
    let result = {};
    let prefix = "{txAuthSimple:";
    if (typeof e == "string" && e.indexOf("{txAuthSimple:") == 0) {
        result.txAuthSimple = e.substring(prefix.length, e.length-1);
    }
    return result;
}

function serializeAuthData(ad) {
    let result = null;
    let adBytes = [];
    adBytes.push(...b64toBA(b64utob64(ad.rpIdHash)));
    adBytes.push(...b64toBA(hextob64(ad.flags)));
    adBytes.push(...[((ad.count & 0xFF000000) >> 24) & 0xFF,((ad.count & 0x00FF0000) >> 16) & 0xFF,((ad.count & 0x0000FF00) >> 8) & 0xFF,(ad.count & 0x000000FF)]);
    if (ad.at) {
        // include attested credential
    }
    if (ad.ed) {
        // include extensions
        
        adBytes.push(...bytesFromArray(new Uint8Array(CBOR.encode(hackExtensions(ad.extensions))),0,-1));
    }

    result = hextob64u(BAtohex(adBytes));
    return result;
}

function serializeAttestationData(ad) {
    // the attestationData is a couple of non-formally structured strings that we need to parse out into a proper attestationObject
    let result = null;
    let aoBytes = [];

    try {

        let aoJSON = {};

        let attStmtStr = ad.attStmt;    
        let authDataStr = ad.authData;

        let attestationType = attStmtStr.match(/{attestationType:([^,]*)/)[1];
        if (attestationType != "SELF") {
            throw ("Unsupported attestationType: " + attestationType);
        }

        let sigStr = attStmtStr.match(/sig:([^}]*)}/)[1];
        let sigBytes = b64toBA(b64utob64(sigStr));

        aoJSON.fmt = "packed";
        aoJSON.attStmt = {
            alg: -7,
            sig: sigBytes
        };

        let adBytes = [];
        let rpIdHashStr = authDataStr.match(/rpIdHash:([^,]*),/)[1];
        adBytes.push(...b64toBA(b64utob64(rpIdHashStr)));
        let flagsStr = authDataStr.match(/flags:([^,]*),/)[1];
        adBytes.push(...b64toBA(hextob64(flagsStr)));
        let counterStr = authDataStr.match(/count:([0-9]*)/)[1];
        let counter = parseInt(counterStr);
        adBytes.push(...[((counter & 0xFF000000) >> 24) & 0xFF,((counter & 0x00FF0000) >> 16) & 0xFF,((counter & 0x0000FF00) >> 8) & 0xFF,(counter & 0x000000FF)]);
        let atFlagStr = authDataStr.match(/at:([^,]*)/)[1];
        if (atFlagStr != "true") {
            throw "Expected at flag to be true for attestation";
        }
        let aaguidStr = authDataStr.match(/aaGuid:([^,]*)/)[1];
        adBytes.push(...b64toBA(hextob64(aaguidStr.replace(/-/g,""))));
        let credIdStr = authDataStr.match(/credentialId:([^,]*)/)[1];
        let credIdBytes = b64toBA(b64utob64(credIdStr));
        let credIdLenArray = [ (credIdBytes.length - (credIdBytes.length & 0xFF)) / 256, credIdBytes.length & 0xFF ];
        adBytes.push(...credIdLenArray);
        adBytes.push(...credIdBytes);
        let coseKeyStr = authDataStr.match(/coseKey:([^,]*)/)[1];
        let coseKey = credentialPublicKeyStringToCOSEKey(coseKeyStr);
        adBytes.push(...bytesFromArray(new Uint8Array(CBOR.encode(coseKey)),0,-1));
        let edFlagStr = authDataStr.match(/ed:([^,]*)/)[1];
        if (edFlagStr != "false") {
            throw "Unexpected extensions flag during attestation";
        }


        aoJSON.authData = adBytes;



        // CBOR encode aoJSON to bytes
        aoBytes = bytesFromArray(new Uint8Array(CBOR.encode(aoJSON)),0,-1);
    } catch (e) {
        console.log(e);
    }

    result = hextob64u(BAtohex(aoBytes));
    return result;
}

function buildFIDOMessageElementsFromAuditRecord(ar) {
    let result = {};

    result.id = ar.event.CommonBaseEvent.extendedDataElements.details.credentialId;
    result.rawId = result.id;

    // both attesation and assertion audit records should contain clientData
    if (ar.event.CommonBaseEvent.extendedDataElements.details.clientData != null) {
        result.clientDataJSON = b64tob64u(utf8tob64(JSON.stringify(ar.event.CommonBaseEvent.extendedDataElements.details.clientData)));
        result.type = "public-key";
    }

    // is this an attestation audit record?
    if (ar.event.CommonBaseEvent.extendedDataElements.details.attestationData != null) {
        if (ar.event.CommonBaseEvent.extendedDataElements.details.registration.credentialId != null) {
            result.id = ar.event.CommonBaseEvent.extendedDataElements.details.registration.credentialId;
            result.rawId = result.id;
        }

        result.attestationObject = serializeAttestationData(ar.event.CommonBaseEvent.extendedDataElements.details.attestationData);

    } else if (ar.event.CommonBaseEvent.extendedDataElements.details.authData != null) {

        result.authenticatorData = serializeAuthData(ar.event.CommonBaseEvent.extendedDataElements.details.authData);

        if (ar.event.CommonBaseEvent.extendedDataElements.details.credentialId != null) {
            result.id = ar.event.CommonBaseEvent.extendedDataElements.details.credentialId;
            result.rawId = result.id;    
        }

        if (ar.event.CommonBaseEvent.extendedDataElements.details.signature != null) {
            result.signature = ar.event.CommonBaseEvent.extendedDataElements.details.signature;
        }

        if (ar.event.CommonBaseEvent.extendedDataElements.details.registration != null) {
            result.registeredCOSEKey = credentialPublicKeyStringToCOSEKey(ar.event.CommonBaseEvent.extendedDataElements.details.registration.publicKey);
        }
    }
    
    return result;
}

let registrationAuditRecord = {"app":"ISVA","hostname":"fidointerop-isamconfig-94dcfc564-qrznh","processId":1311,"priority":14,"event":{"CommonBaseEvent":{"sequenceNumber":"32","extensionName":"IBM_SECURITY_AUTHN","creationTime":"2024-01-09T05:09:05.591Z","globalInstanceId":"FIMec9fcfb9018c1a0dba8dc46597524","contextDataElements":{"name":"Security Event Factory","contextId":"123456789+123456789+123456789+12","type":"eventTrailId"},"extendedDataElements":{"severity":"INFO","userInfoList":{},"fido2Ceremony":"attestation","handle":"314234318","message":"attestation result successfully verified","userId":"2y-xpHfkQSa2Fz9u0tAs9A","relyingParty":"fidointerop.securitypoc.com","fido2Request":"result","eventTime":"1704776945591","authnType":"Not Available","details":{"attestationData":{"attStmt":"{attestationType:SELF,x5c:null,sig:MEUCIQDgF09RcnNeONXujtN5h1Pyz2zRqxWXfj4mwmEhoAnHZgIgN4DmmBKUXlyFyndeIl4-QJfB7_GGFrjC6c7j8CKqrMU}","authData":"{credentialId:RvfzaFV78PW_v4U9XgPTa2yBOuXECMsb0f-AQrZsvilKm7EZ7qntp9EKuj98Eg_-izWkExC21ghtuj0P87JYAMh9MIUCF2pJdM6HXYLAqhQWiz0cXFOe6rv9haNluadYS2DNPTYLVsTR7MoJ9KUKnQ,flags:45,up:true,uv:true,at:true,ed:false,be:false,bs:false,rpIdHash:9rebzUj0SQWZ5fw2CRoiUTVpd_XyX7k6EGgB2mHpBO4,aaGuid:6DC9F22D-2C0A-4461-B878-DE61E159EC61,coseKey:v2EzYi03Yi0xAWItMlggTiVhWO5uHOOFB3pQYXxKH93tWaBk2YhaINbSjtSY8bdhMQJhMyZiLTNYIBtbHVfWjjRrrwcXjL6HQgiLh8Il8FoBhcmtn8dw1UFM_w,count:1704776944}","fmt":"packed"},"authenticatorAttachment":"bad","registration":{"format":"packed","count":1704776944,"userVerified":true,"handle":-775837748,"attestationType":"SELF","backupEligibility":false,"userId":"2y-xpHfkQSa2Fz9u0tAs9A","version":2,"lastUsed":1704776945562,"clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL2ZpZG9pbnRlcm9wLnNlY3VyaXR5cG9jLmNvbSIsImNoYWxsZW5nZSI6IlA0VXgwTDRocE5vdVZaMVpVdjk3ZjZfN240SW80WmZ0WVNNUFpPWkUtNE0iLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0","createdDate":1704776945562,"aaGuid":"6DC9F22D-2C0A-4461-B878-DE61E159EC61","future":"{flags:45}","credentialId":"RvfzaFV78PW_v4U9XgPTa2yBOuXECMsb0f-AQrZsvilKm7EZ7qntp9EKuj98Eg_-izWkExC21ghtuj0P87JYAMh9MIUCF2pJdM6HXYLAqhQWiz0cXFOe6rv9haNluadYS2DNPTYLVsTR7MoJ9KUKnQ","credentialPublicKey":"v2EzYi03Yi0xAWItMlggTiVhWO5uHOOFB3pQYXxKH93tWaBk2YhaINbSjtSY8bdhMQJhMyZiLTNYIBtbHVfWjjRrrwcXjL6HQgiLh8Il8FoBhcmtn8dw1UFM_w","userPresent":true,"attributes":"{attestationObject:o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnmEcYMBhFAhghABjgFxhPGFEYchhzGF4YOBjVGO4YjhjTGHkYhxhTGPIYzxhsGNEYqxUYlxh-GD4YJhjCGGEYIRigCRjHGGYCGCAYNxiAGOYYmBIYlBheGFwYhRjKGHcYXhgiGF4YPhhAGJcYwRjvGPEYhhYYuBjCGOkYzhjjGPAYIhiqGKwYxWhhdXRoRGF0YZkBNxj2GLcYmxjNGEgY9BhJBRiZGOUY_Bg2CRgaGCIYURg1GGkYdxj1GPIYXxi5GDoQGGgBGNoYYRjpBBjuGEUYZRicGNQY8BhtGMkY8hgtGCwKGEQYYRi4GHgY3hhhGOEYWRjsGGEAGHAYRhj3GPMYaBhVGHsY8Bj1GL8YvxiFGD0YXgMY0xhrGGwYgRg6GOUYxAgYyxgbGNEY_xiAGEIYthhsGL4YKRhKGJsYsRgZGO4YqRjtGKcY0QoYuhg_GHwSDxj-GIsYNRikExAYthjWCBhtGLoYPQ8Y8xiyGFgAGMgYfRgwGIUCFxhqGEkYdBjOGIcYXRiCGMAYqhQWGIsYPRgcGFwYUxieGOoYuxj9GIUYoxhlGLkYpxhYGEsYYBjNGD0YNgsYVhjEGNEY7BjKCRj0GKUKGJ0YpRhhGDECGGEYMxgmGGIYLRgxARhiGC0YMhiYGCAYGBhOGBgYJRgYGGEYGBhYGBgY7hgYGG4YGBgcGBgY4xgYGIUHGBgYehgYGFAYGBhhGBgYfBgYGEoYGBgfGBgY3RgYGO0YGBhZGBgYoBgYGGQYGBjZGBgYiBgYGFoYGBggGBgY1hgYGNIYGBiOGBgY1BgYGJgYGBjxGBgYtxhiGC0YMxiYGCAYGBgbGBgYWxgYGB0YGBhXGBgY1hgYGI4YGBg0GBgYaxgYGK8HFxgYGIwYGBi-GBgYhxgYGEIIGBgYixgYGIcYGBjCGBgYJRgYGPAYGBhaARgYGIUYGBjJGBgYrRgYGJ8YGBjHGBgYcBgYGNUYGBhBGBgYTA,clientDataJSON:eyJvcmlnaW4iOiJodHRwczovL2ZpZG9pbnRlcm9wLnNlY3VyaXR5cG9jLmNvbSIsImNoYWxsZW5nZSI6IlA0VXgwTDRocE5vdVZaMVpVdjk3ZjZfN240SW80WmZ0WVNNUFpPWkUtNE0iLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0}","backupState":false,"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnmEcYMBhFAhghABjgFxhPGFEYchhzGF4YOBjVGO4YjhjTGHkYhxhTGPIYzxhsGNEYqxUYlxh-GD4YJhjCGGEYIRigCRjHGGYCGCAYNxiAGOYYmBIYlBheGFwYhRjKGHcYXhgiGF4YPhhAGJcYwRjvGPEYhhYYuBjCGOkYzhjjGPAYIhiqGKwYxWhhdXRoRGF0YZkBNxj2GLcYmxjNGEgY9BhJBRiZGOUY_Bg2CRgaGCIYURg1GGkYdxj1GPIYXxi5GDoQGGgBGNoYYRjpBBjuGEUYZRicGNQY8BhtGMkY8hgtGCwKGEQYYRi4GHgY3hhhGOEYWRjsGGEAGHAYRhj3GPMYaBhVGHsY8Bj1GL8YvxiFGD0YXgMY0xhrGGwYgRg6GOUYxAgYyxgbGNEY_xiAGEIYthhsGL4YKRhKGJsYsRgZGO4YqRjtGKcY0QoYuhg_GHwSDxj-GIsYNRikExAYthjWCBhtGLoYPQ8Y8xiyGFgAGMgYfRgwGIUCFxhqGEkYdBjOGIcYXRiCGMAYqhQWGIsYPRgcGFwYUxieGOoYuxj9GIUYoxhlGLkYpxhYGEsYYBjNGD0YNgsYVhjEGNEY7BjKCRj0GKUKGJ0YpRhhGDECGGEYMxgmGGIYLRgxARhiGC0YMhiYGCAYGBhOGBgYJRgYGGEYGBhYGBgY7hgYGG4YGBgcGBgY4xgYGIUHGBgYehgYGFAYGBhhGBgYfBgYGEoYGBgfGBgY3RgYGO0YGBhZGBgYoBgYGGQYGBjZGBgYiBgYGFoYGBggGBgY1hgYGNIYGBiOGBgY1BgYGJgYGBjxGBgYtxhiGC0YMxiYGCAYGBgbGBgYWxgYGB0YGBhXGBgY1hgYGI4YGBg0GBgYaxgYGK8HFxgYGIwYGBi-GBgYhxgYGEIIGBgYixgYGIcYGBjCGBgYJRgYGPAYGBhaARgYGIUYGBjJGBgYrRgYGJ8YGBjHGBgYcBgYGNUYGBhBGBgYTA","friendlyName":"postman-packed-self-iDDN5UuHFz"},"clientData":{"origin":"https:\/\/fidointerop.securitypoc.com","challenge":"P4Ux0L4hpNouVZ1ZUv97f6_7n4Io4ZftYSMPZOZE-4M","type":"webauthn.create"}},"eventGroup":"16","outcome":{"result":"SUCCESSFUL","majorStatus":0}},"version":"1.1","sourceComponentId":{"threadId":"Default Executor-thread-1553","componentType":"http:\/\/www.ibm.com\/namespaces\/autonomic\/Tivoli_componentTypes","component":"Authentication and Federated Identity","application":"IBM Security Verify Access","locationType":"FQHostname","location":"fidointerop-isamruntime-58f748756d-29n9r","subComponent":"logAuditEvent","executionEnvironment":"Linux[amd64]#5.4.0-167-generic","componentIdType":"ProductName"},"situation":{"situationType":{"reportCategory":"SECURITY","reasoningScope":"INTERNAL","xsi_ns-sep_type":"ReportSituation"},"categoryName":"ReportSituation"}}},"version":1,"timestamp":"2024-01-09T15:09:05.597Z"}
let assertionAuditRecord = {"app":"ISVA","hostname":"fidointerop-isamconfig-94dcfc564-qrznh","processId":1311,"priority":14,"event":{"CommonBaseEvent":{"sequenceNumber":"30","extensionName":"IBM_SECURITY_AUTHN","creationTime":"2024-01-09T04:59:16.949Z","globalInstanceId":"FIMec96d456018c1f8cb227c46597524","contextDataElements":{"name":"Security Event Factory","contextId":"123456789+123456789+123456789+12","type":"eventTrailId"},"extendedDataElements":{"severity":"INFO","userInfoList":{},"fido2Ceremony":"assertion","handle":"142194680","message":"assertion result successfully verified","userId":"2y-xpHfkQSa2Fz9u0tAs9A","relyingParty":"fidointerop.securitypoc.com","fido2Request":"result","eventTime":"1704776356948","authnType":"Not Available","details":{"authenticatorAttachment":"bad","authData":{"uv":true,"bs":false,"extensions":"{txAuthSimple:Test:txn}","rpIdHash":"9rebzUj0SQWZ5fw2CRoiUTVpd_XyX7k6EGgB2mHpBO4","at":false,"be":false,"flags":"85","count":1704776355,"up":true,"ed":true},"signature":"MEUCIQD4oYpk_Ho4DbWKP0ycHksmZ9mbJhqSc_fWtvBrmqB1gwIgBgGMYLz5dE_Msl7kWAwVYIBw9U9MkWfPXu-ZO843MFI","credentialId":"pvP-kECtGzhZauhvvA9YizkNTLKc_5kltA-aSbXlmG5lq0Ps6Gn4U6bzgGMHB3YP0mH6SfIrVLjwWTQWgXf-wa0gv-ybuhdigb-a2LJW_FAM3MeP_A-CXyDl5NqDOcU1_6fZPA4sOp9TAIP43BCa4Q","registration":{"metadata":"{description:IBM-FIDO2APP,icon:data:image\/png;base64,iVBORw0KGgoAAAANSUhEUgAAADoAAAA6CAYAAADhu0ooAAAAAXNSR0IArs4c6QAAAERlWElmTU0AKgAAAAgAAYdpAAQAAAABAAAAGgAAAAAAA6ABAAMAAAABAAEAAKACAAQAAAABAAAAOqADAAQAAAABAAAAOgAAAACjq6v0AAALPklEQVRoBe1bC1BU1xn+9g0sD0EU8VmlRhHxlUZN1CnjqHWiTRu0am3GtHUmTRVHo2M7Y9rGqbWNbYOtEdHE8Z1ajbVmnI6Nba3GqhUfKI4ianipPARdVgR22V22\/3eWuy6wKO10RiD8zN177znnnvN\/\/+v851yuzitUUlKClStX4siRI6iqqoIUoT2QTq+DOdKM+Im9kDB7EHjv9QhvuqdzF2IMwdi+45A2Ng0xod2hu3v3rnfq1Km4du3a059+hi1iR8Vi1PIR8Da0TQleeFHtrEZSz+H47bT3YBCgq48fPw6TyYSGhoZnCKWVoUV7OqMOtSW1MEeZ0T0pGh6nBzrdk9WqE7WHm8NRZC9SgHVWq9VbV1fXPkE2YqfJioIQkxyD51eNhrvWrcy4FdE0KaZmQ42hMNbU1DSpaK83jBvuOrfy0adpMxADNetwO6APLOzM111AO5t2uzTapdEOKoEu0+2gimuV7S6NtiqaDlrxhdGosYMqyM+2QW\/wX\/OCOXGDt+UqrMMCZbLu9rphq7GpJZtelm0NAtJsMMNqssqapem6tUMC5erF1eBCj7AeWDr+Lbg9Ljg9TnBX4cb9G\/j01l9h0puagG0VKDvT6\/X+BS5NwuPxNDGTZ31D\/swGEwZ3H4y+kX1RVFWI4T2TcTjvE6XZwC2hoMGIIDVgbrcbPAJBSrUIQVb+PD95oa\/aGA068DA8rXEbJUfeqLH7tffx1pFl2HlpO3LKL2Pz+c1K002N1tdpC41qIFnNvaTRo0erbZabN2\/i0KFDqK+vFyHQ6X0dBOvUV9NYLw3c3ND6PxN9UK\/TIyYsRrxVh4qaCkRaIv0W2Hw46sPPBU2B0oqLi8PevXuRkpLib19aWoqBAwfC6XRiQJwFm1d8GWFhBixJ\/xw5+TVKw4FbTlpwGBQfgp8s6KdUf6fMgZ9tL\/b32dYLtfsnm2JRg6MwdvVX0FAvUVVZk14FHiqHkTZCgEZYwpFbkQujzvh0H929e7cCyc0ygift27dPgeT126\/1w\/SpPQBx2d+86cHXfnRVSTVAZspkKcL47mZ8b04fQEy3+Hp1m4Fq8SHYhh2BMfgMjB6I91\/OIEsKKDWbdTcLOWXvKCsM9FG\/6RoMBqXN5ORkTJkyRfmkw+HAsmXL1FZocXExTLIb5xEzvFPh9DmnMF9ULtcB5PNf8UnxR5qKyy17PVUuBdRW7Q5o6bvUAGkuQ2BkMBAg6wJJ+agEobJH5fjB4Tca502fKbsb3LAYLI1lj5\/yA9U679+\/vxqIwE+cOIGtW7c+bt149fNdt1FucyEsxIBNh0ppRdKxVwUbj5gYhcGDZBCDYCCiRgODEZknyMAgpx6Qn+joaEyaNAkRERE4deoUCosKtSp15rOcXmLDYpE2bomYb5gCRgw55TnYnr0NFqNF4dAe9AMNDQ1Fr169MGDAAL9DG41GDBkyBFX2h3A+uofYaLPahSOEj09UKvO0hurhdImJy+AEGR1uxMSRkegWYUJ2XjVqHKIhaR+oE017BNmvXz+MHDkSUVFRqKiowLlz52Cz2VBWVob4+Hg\/LxrD2tkjmosJicGIuBHYdWmnMuXhsln9Ur+X8OGFDxAif4FJg5Ga44BDhw7F2bNntX7UefLkycpsV69NR\/npd5C5djzqK+pgFBMW4cHUzYSNot0l7+eLqXkx56uxWL88Ab1jLYBFVCmmevScTXzbgxARAEkzwzARbPr69Zg\/f77SnKqUHwa9tWvXIiMjA1lZWapYBSMOGED0R2rVVmfD1gsf4ra9GIvk9UN8UrwIvOV879co+yDo5vTYh8QtaX6NJqhNGQRNmpgciX1rEyVACUOeBthL65VPT5vcA+4H9SpO0dU0oPv378eMmTPVs3a7HYWFhUqz1OLGjRtV+aZNmxRPzRmniVpkU\/rmg5uo99Rj26s7cKb4NBaOWYgtF7Yo86EgAkmv+cj169eRmJiIpUuX+uvpo8OGDcPmje9h30kHRsz6N5K\/n41f\/\/EujDK1eCXQaIL+aeMU4pH+\/3L6AZIXZiPx9Yv49J8VMEhbyIxAQTLIvPLKNxRIJiLU4IQJEzBq1CgsXrxY+RXbrFmzRpkz22jC8TMmF4RBMD\/+20oU2PIxuvcYbDi7AQev\/QkR5giRd1Ot+uYOeYivJQi2oKDA3x8lnZubi3vlpah61IArn9cg73Yd7laKhhqjKv2TwWZcYgS8TvFHAb8iowC37zlRLMcvdt4OkK1PyqmpryrAjAE7duzA1atXlRCowfz8fBWkGJDGjRuneKFVBSMmDHaHXVK\/IpRWl6CwqgCMusEE4++BnfGwWMS\/GomMsIxnmp3ZxDbim2KuOrNETYm6nD6irAaEhxqgE8VV3K9HqRzM9ni4aMouOeRamzL69Omj+uUwFK42Bs9FRUVqdJon25GCMc5yBqT06b\/D3OHz1PuVDS9vxIznZuCR85GM7YfGpmjio2SEA2jEa5ZxIBYz4MgtIsQU\/3XGBnutB90kyDgkU2GdoUEHq9SZTSIIh28eZTkaXV9jmNkV++Y9pxASQXIs7Z51fFdLCuSJ96yrddXg+d4voFd4L8z7eA5KRKMLRr2ObyXNkaT+MJs1oaawm1S1fhMi2rxZVIvLMn1EhRvUFFIi5szlbqRMQd+dHqemGoKc8WIMvEYZhsCoYqELFy4oZgksNTVVAaTrJCQkICkpSc0CjB0XL15U7b2UbguiIH3lmgCZ9rVGLWooPQYAkhaomj\/MZMAkzNOUfawDH\/29AqvSBqGu3IFfvvEl5bOUYuq0nvKaTwKDmLvL5XuvuW3bNqxYsRyhoWFISUnBzp07cebMGSxatEi5DoPWnj17VCRWAazZjgF5DJMk4VLZJTWt7E79CFfuXcG0hGl49+SvfNbi58zHfQuN0kfpkzw4iQcjq\/gjzdcqcyV9k\/Tu3jv47LNKhMaFwCS+O\/ub8Uid3xdZl+yokvnUKAuBKKtvfVtQUIC5c+fh4cOHymQXLFiAzMxMMP0ksKNHjyItLc1vzsF4YJlZb8bb\/1iFT64fEjkaZMm2FH\/OlahraRl1yeVqPkSipAiQJsUM5dixY34zU37S6KsW0WRhmRO5RXUoKHUi+1YN6iXg7DtWiVqCEjUXFdZi18FSvJl+C9V1HuTfduBYlg0nc+wKQF5eHg4cOADm0zw4zTBhWbdunfp\/CvqxxpMyTXH1kO4h6JPSW01VDo8DA7oNwPrpv8cHsg7NPJchQenb6GmNw7XKa2q3ITAzouU9jj6q6\/\/tR2RAN2wzacGntQcITglXGjRfpnlFqAQ6OGYwMr++RU0xc\/bPVhE3NXEWXjv4HTWXBm6StfBRDkDzIXGgYH4qAVI8wBdVKSnmuARJsEzcGYSImdesYx7MOrbhPYlWQ7AaYI7Fa61OA6kKgvyo9ackBjcq83C+5Dz2zPoDiiUNtDlksyxI+xZAOYAWjIK0V0W+IOhjOLANgWipIcu1aw8rghDB8tAomFC1uuZng\/jkg7oHuFx2Wcx2E2pkuhnc\/Tnsyt4h2yyy+GhmqAQfnIvmPT\/D++amyx0GWh7TPC7Aub1pd9rFWjzynyjWoEBbaPQZ4vmvhqbGqFWCpBl3s3SjP\/nXpc0767BACYRgNV9WSfwTbLPFPNpcEp3lvgtoZ9GkhqNLo5okOsu5S6OdRZMaji6NapLoLOcujXYWTWo49PKv5v51oFbYHs9crRhDZdtV9pC1\/LYtfDIf5v826GfKawGuCfnxQLskLiTFwQiux5hY9VqkrXzy9T+\/lBjf90Xo09PT1WsHl0veYbZHkhUJd\/\/5OUjfyX3gqmnbhwPU5P26++pzkB++sAg6kdQX4gOf\/wDW8hWHrT7NEgAAAABJRU5ErkJggg==}","created":"2024-01-04T23:41:22.038Z","flags":"{up:true,uv:true,at:true,ed:false,be:false,bs:false}","format":"packed","userVerified":true,"backupEligibility":false,"attestationType":"Self","counter":1704776355,"publicKey":"v2EzYi03Yi0xAWItMlggOpAMrYRycyYoGPSM1PLfJDfgTb2ypq-KZm6i4PmMYcJhMQJhMyZiLTNYIIO6lTHuM0ToLSq8mN-qsPqj8WcnJHLIB6fWmf97YaeL_w","rpId":"fidointerop.securitypoc.com","version":2,"userId":"DB2FB1A477E44126B6173F6ED2D02CF4","enabled":true,"lastUsed":"2024-01-09T04:59:16.942Z","aaGuid":"6DC9F22D-2C0A-4461-B878-DE61E159EC61","future":"{flags:45}","nickname":"postman-packed-self-xahG1sZYR3","credentialId":"pvP-kECtGzhZauhvvA9YizkNTLKc_5kltA-aSbXlmG5lq0Ps6Gn4U6bzgGMHB3YP0mH6SfIrVLjwWTQWgXf-wa0gv-ybuhdigb-a2LJW_FAM3MeP_A-CXyDl5NqDOcU1_6fZPA4sOp9TAIP43BCa4Q","userPresent":true,"attributes":"{clientDataJSON:eyJvcmlnaW4iOiJodHRwczovL2ZpZG9pbnRlcm9wLnNlY3VyaXR5cG9jLmNvbSIsImNoYWxsZW5nZSI6ImpLbzF1QW9xQjdEQk9jSTRjY245TmlEQVo4dlZMN01HRDZ4NUtCTG5NVkEiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0,attestationObject:o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnmEcYMBhFAhggGE4YrRjKGHYYwRg4GGMYiRjDGLcYgBhQGKkYOxjOGLUY6Ri2GO0YTRhxGCwYZRhQGHEOGFAYJAIYLBg4GIUCGCEAGIoYXhhQGO8YuxhVGDMYmBhdGFoYGBjJGO8YPBjgGGEYORg9GIEY7RgtGJMYHRUYOxieGOIYlxiJGOUYohjLaGF1dGhEYXRhmQE6GPYYtxibGM0YSBj0GEkFGJkY5Rj8GDYJGBoYIhhRGDUYaRh3GPUY8hhfGLkYOhAYaAEY2hhhGOkEGO4YRRhlGJcYQhghGG0YyRjyGC0YLAoYRBhhGLgYeBjeGGEY4RhZGOwYYQAYcBimGPMY_hiQGEAYrRgbGDgYWRhqGOgYbxi8DxhYGIsYOQ0YTBiyGJwY_xiZGCUYtA8YmhhJGLUY5RiYGG4YZRirGEMY7BjoGGkY-BhTGKYY8xiAGGMHBxh2DxjSGGEY-hhJGPIYKxhUGLgY8BhZGDQWGIEYdxj-GMEYrRggGL8Y7BibGLoXGGIYgRi_GJoY2BiyGFYY_BhQDBjcGMcYjxj8DxiCGF8YIBjlGOQY2hiDGDkYxRg1GP8YpxjZGDwOGCwYOhifGFMAGIMY-BjcEBiaGOEYpRhhGDECGGEYMxgmGGIYLRgxARhiGC0YMhiYGCAYGBg6GBgYkAwYGBitGBgYhBgYGHIYGBhzGBgYJhgYGCgYGBgYGBgY9BgYGIwYGBjUGBgY8hgYGN8YGBgkGBgYNxgYGOAYGBhNGBgYvRgYGLIYGBimGBgYrxgYGIoYGBhmGBgYbhgYGKIYGBjgGBgY-RgYGIwYGBhhGBgYwhhiGC0YMxiYGCAYGBiDGBgYuhgYGJUYGBgxGBgY7hgYGDMYGBhEGBgY6BgYGC0YGBgqGBgYvBgYGJgYGBjfGBgYqhgYGLAYGBj6GBgYoxgYGPEYGBhnGBgYJxgYGCQYGBhyGBgYyAcYGBinGBgY1hgYGJkYGBj_GBgYexgYGGEYGBinGBgYiw}","backupState":false,"username":"https:\/\/login.ibm.com\/oidc\/endpoint\/default\/110000r98v"},"clientData":{"origin":"https:\/\/fidointerop.securitypoc.com","challenge":"xvUrw8Gp2ExxMJ0c1F4JG0M5RLkBSqQaABIhXL9Caak","type":"webauthn.get"}},"eventGroup":"16","outcome":{"result":"SUCCESSFUL","majorStatus":0}},"version":"1.1","sourceComponentId":{"threadId":"Default Executor-thread-1555","componentType":"http:\/\/www.ibm.com\/namespaces\/autonomic\/Tivoli_componentTypes","component":"Authentication and Federated Identity","application":"IBM Security Verify Access","locationType":"FQHostname","location":"fidointerop-isamruntime-58f748756d-29n9r","subComponent":"logAuditEvent","executionEnvironment":"Linux[amd64]#5.4.0-167-generic","componentIdType":"ProductName"},"situation":{"situationType":{"reportCategory":"SECURITY","reasoningScope":"INTERNAL","xsi_ns-sep_type":"ReportSituation"},"categoryName":"ReportSituation"}}},"version":1,"timestamp":"2024-01-09T14:59:16.955Z"}

console.log("Rebuilt attestation payload from attestation audit record: " + JSON.stringify(buildFIDOMessageElementsFromAuditRecord(registrationAuditRecord)));
console.log("Rebuilt assertion payload from attestation audit record: " + JSON.stringify(buildFIDOMessageElementsFromAuditRecord(assertionAuditRecord)));

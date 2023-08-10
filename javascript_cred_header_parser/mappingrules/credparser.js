//
// Defines a function called decodePACHeader which can parse the iv-creds HTTP header value
//

//
// Can be used from multiple JS contexts - include InfoMap mapping rules, and template page scripting.
// Use from InfoMap is very straight forward. Use from template scripting is also possible, but perhaps
// less obvious.
//

//
// To use this from a page template scripting context:
// 1. Load the mapping rules 
//      - ASN1 with contents of asn1tools.js 
//      - CredParser with contents of credparser.js
// 2. Set advanced config parameter sps.httpRequestClaims.enabled=true
// In your page template, build the JSON stsuu as follows (defining debugLog is optional):
// <%
//
//    importMappingRule("CredParser");
//    
//    function debugLog(s) {
//    	templateContext.response.body.write("<!-- debug: "+ s +" -->");
//    }
//
//    let stsuu = decodePACHeader(templateContext.request.headers["iv-creds"][0]);
//
// %>
//

// requires asn1tools.js loaded as a mapping rule called "ASN1"
if (typeof importMappingRule != "undefined") {
	importMappingRule("ASN1");	
}


// helper functions
function bytesToHexString(byteArray) {
	let result = '';
	byteArray.forEach((b) => {
		result += (('0' + (b & 0xFF).toString(16)).slice(-2));
	});
	return result;
}

// an internal debug function - to leverage debugging, just define your own debugLog function
function credParserDebug(s) {
	// if there is a debugLog function defined, use it
	if (typeof debugLog == "function") {
		debugLog(s);
	}
}

//
// unpacks the elements of a UUID in a PAC and constructs the UUID string
// corresponds to the struct uuid_t
//
function parseUUID(uuidSequence) {
	let result = null;
	if (uuidSequence != null && uuidSequence.tag != null && uuidSequence.tag.tagNumber == 16 && uuidSequence.sub.length == 6) {
		// extract integer parts of the UUID as bytes and convert to hex strings, taking into account that the first integer should be 8 hex chars
		// the second should be 4 chars, the third should be 4 chars, and the 4th and 5th are two chars
		// note that for gi4Hex and gi5Hex we expect these to be two hex chars so slice to that
		//
		// The portions of the UUID are:
		// time_low
		// time_mid
		// time_hi_and_version
		// clock_seq_hi_and_reserved
		// clock_seq_low
		// node (6 bytes)
		// 
		let gi1HexStr = ("00000000" + bytesToHexString(uuidSequence.sub[0].stream.enc.slice(uuidSequence.sub[0].posContent(), uuidSequence.sub[0].posEnd()))).slice(-8);
		let gi2HexStr = ("0000" + bytesToHexString(uuidSequence.sub[1].stream.enc.slice(uuidSequence.sub[1].posContent(), uuidSequence.sub[1].posEnd()))).slice(-4);
		let gi3HexStr = ("0000" + bytesToHexString(uuidSequence.sub[2].stream.enc.slice(uuidSequence.sub[2].posContent(), uuidSequence.sub[2].posEnd()))).slice(-4);
		let gi4HexStr = ("00" + bytesToHexString(uuidSequence.sub[3].stream.enc.slice(uuidSequence.sub[3].posContent(), uuidSequence.sub[3].posEnd()))).slice(-2);
		let gi5HexStr = ("00" + bytesToHexString(uuidSequence.sub[4].stream.enc.slice(uuidSequence.sub[4].posContent(), uuidSequence.sub[4].posEnd()))).slice(-2);
		
		// same for the octet string portion - up to 12 hex chars (6 bytes)
		let octetHexStr = ("000000000000" + bytesToHexString(uuidSequence.sub[5].stream.enc.slice(uuidSequence.sub[5].posContent(), uuidSequence.sub[5].posEnd()))).slice(-12);
		
		// put the pieces into a string uuid
		// including converting the octect string portion to hex
		result = gi1HexStr + "-" + gi2HexStr + "-" + gi3HexStr + "-" + gi4HexStr + gi5HexStr + "-" + octetHexStr;
	} else {
		credParserDebug("parseUUID: Invalid uuidSequence");
	}
	return result;
}

//
// unpacks the basic structure used to identify principals and groups
// it contains the UUID and an optional string name 
// corresponds to the struct sec_id_t
//
function parseSecId(nameAndUUIDSequence) {
	let result = null;
	
	// principals and groups look like this - a sequence with one or two elements - the first is a UUID sequence, and then if present, a UTF8String for the name
	if (nameAndUUIDSequence.sub.length == 1 || nameAndUUIDSequence.sub.length == 2) {
		let uuid = parseUUID(nameAndUUIDSequence.sub[0]);

		let name = null;
		if (nameAndUUIDSequence.sub.length == 2 && nameAndUUIDSequence.sub[1] != null && nameAndUUIDSequence.sub[1].tag != null && nameAndUUIDSequence.sub[1].tag.tagNumber == 12) {
			name = nameAndUUIDSequence.sub[1].content();
		} else {
			credParserDebug("parseSecId: Invalid name in nameAndUUIDSequence");
		}
		
		if (uuid != null) {
			result = {
				uuid: uuid
			};
			if (name != null) {
				result["name"] = name;
			}
		}
	} else {
		credParserDebug("parseSecId: Invalid nameAndUUIDSequence");
	}
	
	return result; 
}

//
// unpacks a privilege attributes section of a PAC
// corresponds to the struct sec_id_pa_t
//
function decodePrivilegeAttributes(principalAndGroupsSequence) {
	let result = {
		Principal: {}, GroupList: []
	};
	
	// should be a sequence of two (principal then groups), even if no groups
	if (principalAndGroupsSequence.tag.tagNumber == 16 && principalAndGroupsSequence.sub.length == 2) {
		// first the principal
		credParserDebug("decodePrivilegeAttributes: Parsing principal");
		let principalSequence = principalAndGroupsSequence.sub[0];
		let principalObject = parseSecId(principalSequence);
		if (principalObject != null) {
			credParserDebug("principalObject: " + JSON.stringify(principalObject));
			result.Principal = principalObject;
			
			// now the groups
			credParserDebug("decodePrivilegeAttributes: Parsing groups");
			let groupsSequence = principalAndGroupsSequence.sub[1];
			credParserDebug("decodePrivilegeAttributes: Number of groups:  " + groupsSequence.sub.length);

			// this works even if the user is in no groups
			groupsSequence.sub.forEach((g) => {
				let groupObject = parseSecId(g);
					
				if (groupObject != null) {
					result.GroupList.push(groupObject);
				} else {
					// not fatal
					credParserDebug("decodePrivilegeAttributes: Encountered invalid group");		
				}
			});	
			
		} else {
			credParserDebug("decodePrivilegeAttributes: Invalid Principal");
			result = null;
		}
	} else {
		credParserDebug("decodePrivilegeAttributes: Invalid principalAndGroupsSequence");
		result = null;
	}
	
	return result;
}

//
// decodes attribute values
// corresponds to list of struct value_t 
//
function decodeAttributeValues(attributeValuesSequence) {
	let result = [];
	
	// the sequence can contain any number of values
	if (attributeValuesSequence != null && attributeValuesSequence.tag.tagNumber == 16) {
		attributeValuesSequence.sub.forEach((av) => {
			// each value should be a sequence of three things - integer valuetype, a stirng value, and an octet string for bytes value
			// this implementation only deals with string values - others are logged but otherwise ignored
			if (av != null && av.tag.tagNumber == 16 && av.sub.length == 3) {
				let valueTypeElement = av.sub[0];
				let utf8valElement = av.sub[1];
				let bytevalElement = av.sub[2];
				
				if (valueTypeElement != null && valueTypeElement.tag.tagNumber == 2 && valueTypeElement.content() == "4") {
					if (utf8valElement != null && utf8valElement.tag.tagNumber == 12) {
						// a valid value - add it to the result
						result.push(utf8valElement.content());
					} else {
						credParserDebug("decodeAttributeValues: Attribute value utf8val tag was not a string: " + utf8valElement.tag.tagNumber);	
					}
				} else {
					credParserDebug("decodeAttributeValues: Attribute value type was not a string: " + valueTypeElement.content());	
				}
				
				// just check the byte values for presence of non-empty octect string, and log a warning message if anything unusual found
				if (!(bytevalElement != null && bytevalElement.tag.tagNumber == 4 && (bytevalElement.posContent() == bytevalElement.posEnd()))) {
					credParserDebug("decodeAttributeValues: Attribute bytvalElement was not an empty octect-string. TagNumber: " + bytevalElement.tag.tagNumber);
					if (bytevalElement.tag.tagNumber == 4) {
						// dump the bytes that were found
						let bytevalHex = bytesToHexString(bytevalElement.stream.enc.slice(bytevalElement.posContent(), bytevalElement.posEnd()));
						credParserDebug("decodeAttributeValues: Attribute bytvalElement content: " + bytevalHex);
					}
				}
			} else {
				credParserDebug("decodeAttributeValues: Invalid values sequence");
			}			
		});
	} else {
		credParserDebug("decodeAttributeValues: Invalid attributeValuesSequence");
	}
	
	return result;
}

//
// decodes a single attribute
// corresponds to struct attr_t
//
function decodeAttribute(attributeSequence) {
	let result = { name: null, values: []};
	
	// attributes should be a two-element sequence name, and values
	if (attributeSequence != null && attributeSequence.tag.tagNumber == 16 && attributeSequence.sub.length == 2) {
    	// first part should be UTF8String attr name
    	let asn1AttrName = attributeSequence.sub[0];
    	if (asn1AttrName.tag.tagNumber == 12) {
    	
    		result.name = asn1AttrName.content();
    		
    		// second part is attribute values
    		let attributeValuesArray = decodeAttributeValues(attributeSequence.sub[1]);
    		if (attributeValuesArray != null) {
				result.values = attributeValuesArray;
			} else {
				credParserDebug("decodeAttribute: Invalid attribute values");	
			}
    	} else {
			credParserDebug("decodeAttribute: Invalid attribute name");
		}
    } else {
		credParserDebug("decodeAttribute: Invalid attributeSequence");
	}

    return result;
}

//
// decodes an attribute list
// corresponds to struct attrlist_t
//
function decodeAttributeList(attributeListSequence) {
	let result = {};

	// parse the attribute list if we identified it
	// any invalid or unparsable attributes get skipped
	if (attributeListSequence != null && attributeListSequence.tag.tagNumber == 16) {
	    attributeListSequence.sub.forEach((a) => {
			// attributes should be a two-element sequence name, and values
			if (a.tag.tagNumber == 16 && a.sub.length == 2) {
				let attributeObject = decodeAttribute(a);
				if (attributeObject != null) {
					result[attributeObject.name] = attributeObject.values;
				}
			} else {
				credParserDebug("decodeAttributeList: Invalid attribute sequence");
			}
	    });    					
	} else {
		credParserDebug("decodeAttributeList: The attributeListSequence was invalid");
		result = null;
	}

	
	return result;
}

//
// decodes a principal
// corresponds to struct ivprincipal_t
//
function decodePrincipal(principalSequence) {
	let result = { Version: null, Principal: {},  GroupList: [], AuthType: null, AttributeList: {} };
	
	// should be a sequence of three (if unauthenticated) or four elements (authenticated PAC)
	if (principalSequence.tag.tagNumber == 16 && (principalSequence.sub.length == 3 || principalSequence.sub.length == 4)) {
		let firstElement = principalSequence.sub[0];
		let secondElement = principalSequence.sub[1];
		let thirdElement = principalSequence.sub[2];
		let fourthElement = ((principalSequence.length > 3) ? principalSequence.sub[3] : null);
		let attributeListElement = null;
			
		// The version element, should be integer
		if (firstElement.tag.tagNumber == 2) {
			result.Version = firstElement.content();

			// is the secondElement an integer (0) for unauthenticated?
			if (secondElement.tag.tagNumber == 2 && secondElement.content() == "0") {
				credParserDebug("This appears to be an unauthenticated cred");

				result.AuthType = secondElement.content();

				// put some canned values in the Principal
				result.Principal["name"] = "unauthenticated";
				result.Principal["uuid"] = "00000000-0000-0000-0000-000000000000";
				result.Principal["domain"] = "Default";
				result.Principal["registryid"] = "cn=unauthenticated";
				
				
				
				// if the third element is a sequence that contains a single sequence make the subsequence attributeListElement
				if (thirdElement.tag.tagNumber == 16 && thirdElement.sub.length == 1 && thirdElement.sub[0].tag.tagNumber == 16) {
					attributeListElement = thirdElement.sub[0];
				} else {
					// consider this odd, but not fatal
					credParserDebug("decodePrincipal: The credential was unauthenticated, but attribute list could not be found");
				}
			} else if (secondElement.tag.tagNumber == 16 && secondElement.sub.length == 2) {
				// looks like the second element is principal and groups
				let principalAndGroupsObject = decodePrivilegeAttributes(secondElement);
				if (principalAndGroupsObject != null) {
					result.Principal = principalAndGroupsObject.Principal;
					result.GroupList = principalAndGroupsObject.GroupList;
					
					// sanity check the third element is a number "1" for an authenticated credential authentication type
					if (thirdElement.tag.tagNumber == 2) {
						result.AuthType = thirdElement.content();
						
						// if the fourthElement is defined, and a sequence containing one sequence, make that subsequence the attributeSequence
						if (fourthElement != null && fourthElement.tag.tagNumber == 16 && fourthElement.sub.length == 1 && fourthElement.sub[0].tag.tagNumber == 16) {
							attributeListElement = fourthElement.sub[0];
						}
					} else {
						credParserDebug("decodePrincipal: The thirdElement could not be decoded as authtype");	
						result = null;
					}
					
				} else {
					credParserDebug("decodePrincipal: The secondElement could not be decoded as principal and groups");
					result = null;	
				}
				
			} else {
				credParserDebug("decodePrincipal: The secondElement was not recognized");
				result = null;
			}
			
			// if we are still ok, and have an attributeListElement, decode it
			if (result != null && attributeListElement != null) {
				let attributeListObject = decodeAttributeList(attributeListElement);
				
				if (attributeListObject != null) {
					result.AttributeList = attributeListObject;
					
	    			// some attributes also get made part of the Principal
	    			if (attributeListObject["AZN_CRED_PRINCIPAL_DOMAIN"] != null && attributeListObject["AZN_CRED_PRINCIPAL_DOMAIN"].length > 0) {
						result.Principal["domain"] = attributeListObject["AZN_CRED_PRINCIPAL_DOMAIN"][0];
					}
	    			if (attributeListObject["AZN_CRED_REGISTRY_ID"] != null && attributeListObject["AZN_CRED_REGISTRY_ID"].length > 0) {
						result.Principal["registryid"] = attributeListObject["AZN_CRED_REGISTRY_ID"][0];
					}
				} else {
					credParserDebug("decodePrincipal: Could not decode attributeListElement");
					result = null;
				}
			}
		} else {
			credParserDebug("decodePrincipal: Invalid version element");
			result = null;	
		}
	} else {
		credParserDebug("decodePrincipal: Invalid prinicpalSequence");
		result = null;	
	}
		
	return result;
}		

//
// decodes a principal chain
// corresponds to struct ivprincipal_chain_t
// 
function decodePrincipalChain(principalChainSequence) {
	let result = {
		Signature: null,
		PrincipalList: []
	};
	
	// should be a sequence of two (signature then principal chain)
	if (principalChainSequence.tag.tagNumber == 16 && principalChainSequence.sub.length == 2) {
		let signatureString = principalChainSequence.sub[0];
		let principalSequence = principalChainSequence.sub[1];
		
		// first the signature
		if (signatureString != null && signatureString.tag.tagNumber == 12) {
			result.Signature = signatureString.content();
			
			// now the prinicipal chain
			if (principalSequence != null && principalSequence.tag.tagNumber == 16 && principalSequence.sub.length > 0) {
				credParserDebug("decodePrincipalChain: Number of principals:  " + principalSequence.sub.length);
				let failedPrincipals = false;
				principalSequence.sub.forEach((p) => {
					let principalObject = decodePrincipal(p);
					
					// should never happen
					if (principalObject != null) {
						result.PrincipalList.push(principalObject);
					} else {
						failedPrincipals = true;
					}
				});
				
				// sanity check
				if (failedPrincipals) {
					credParserDebug("decodePrincipalChain: One or more principals failed to decode");
					result = null;	
				}
			} else {
				credParserDebug("decodePrincipalChain: Invalid principal chain");
				result = null;
			}
			
		} else {
			credParserDebug("decodePrincipalChain: Invalid Signature");
			result = null;
		}
	} else {
		credParserDebug("decodePrincipalChain: Invalid principalChainSequence");
		result = null;
	}
	
	return result;
}

//
// This is the main function to consume.
//
// Given a string PAC header, decode to JSON stsuu
// This does not account for every possible valid PAC - it only deals with the first principal in the chain, and also deals with unauthenticated PAC
// The pacHeader may include the "Version=1, " prefix - if found this will be stripped off
// Only string values in the attribute list are returned
//
//
function decodePACHeader(pacHeader) {
	let stsuu = null;
	
	if (pacHeader != null) {
		stsuu = { Principal: {}, AttributeList: {}, GroupList: [] };
	
		// pac is base64 encoded with version prefix, but first 4 bytes are a magic prefix to check, and not part of the credential chain ASN1 sequence
		try {
			let credBytes = MyBase64.decode(pacHeader.replace("Version=1, ",""));
			if (credBytes != null && credBytes.length > 4) {
				let credPrefix = credBytes.splice(0,4);

				// validate the prefix - historically, this is the four bytes 0x04 (length) 0x02 (version) 0xAC 0xDC (magic value)
				if (credPrefix != null && credPrefix.length == 4 && credPrefix[0] == 0x04 && credPrefix[1] == 0x02 && credPrefix[2] == 0xAC && credPrefix[3] == 0xDC) {
					//
					// decode the prinicpal chain  
					//
					let asn1PAC = ASN1.decode(credBytes);
					let principalChainObject = decodePrincipalChain(asn1PAC);
					if (principalChainObject != null && principalChainObject.PrincipalList != null && principalChainObject.PrincipalList.length > 0) {
						stsuu = principalChainObject.PrincipalList[0];
					} else {
						credParserDebug("The PAC did not include at least one principal");
					}
				} else {
					credParserDebug("The PAC prefix bytes are incorrect");
				}
			} else {
				credParserDebug("The PAC bytes are too short");
			}	
		} catch (e) {
			credParserDebug("Exception parsing cred: " + e);
			stsuu = null;
		}
	} else {
		credParserDebug("The PAC header string was not supplied");
	}
		
	return stsuu;
}
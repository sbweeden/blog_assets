importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importPackage(Packages.com.ibm.security.access.scimclient);

//this variable changes how we do user lookups of SCIM data
var users_in_scim_user_registry = false;

function computeIDForUsername(username) {
	return ScimClient.computeIDForUsername(username);
}

function getSCIMQueryURL(uname) {
	var attributes = "urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator:userPresenceMethods,urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator:authenticators,urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator:fingerprintMethods,urn:ietf:params:scim:schemas:extension:isam:1.0:U2F:tokens";

	/*
	 * If the user is guaranteed to be in the SCIM user registry, you can use this
	 */
	var result = null;
	if (users_in_scim_user_registry) {
		result = "/Users?filter=userName%20eq%20"+username+"&attributes=" +attributes;
	} else {	
		// in case they're not, let's construct the user URL by computed ID
		result = "/Users/"+computeIDForUsername(uname)+"?attributes=" + attributes;
	}
	
	IDMappingExtUtils.traceString("getSCIMQueryURL("+uname+") : " + result);
	return result;
}

function getSCIMUserRecordFromResults(jobj) {
	var result = null;
	
	// if we did a filter search, we'll get back search results
	if (users_in_scim_user_registry) {
		if (jobj['totalResults'] != null && jobj['totalResults'] == 1) {
				result = jobj.Resources[0];
		}
	} else {
		// if we did a encoded user search, then we get back just the user object or an error
		if (jobj['meta'] != null) {
			result = jobj;
		}
	}
	return result;
}

function isIBMVerifyRegisteredForUser(username) {
	var result = false;

	var scimConfig = context.get(Scope.SESSION, "urn:ibm:security:asf:policy", "scimConfig");
	if (scimConfig != null) {
		var resp = ScimClient.httpGet(scimConfig, getSCIMQueryURL(username));
		if (resp != null && resp.getCode() == 200) {
			var respJson = JSON.parse(resp.getBody());
			IDMappingExtUtils.traceString("SCIM resp: "+respJson.totalResults);
			IDMappingExtUtils.traceString("SCIM resp: "+resp.getBody());
	
			var userObj = getSCIMUserRecordFromResults(respJson);
			if (userObj != null) {
				IDMappingExtUtils.traceString("Found a user with : "+JSON.stringify(userObj));
				
				var mmfaData = userObj['urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator'];
				
				if (mmfaData != null) {
					var authenticators = mmfaData["authenticators"];
	
					IDMappingExtUtils.traceString("authenticators : "+JSON.stringify(authenticators));
					if (authenticators != null && authenticators.length > 0) {
						// there is at least one
						result = true;
					} else {
						// no mmfa authenticators
						IDMappingExtUtils.traceString("no mmfa authenticators");
					}
				} else {
					// no mmfa data, probably not registered
					IDMappingExtUtils.traceString("no mmfa data, probably not registered");
				}
			} else {
				// no userObj - probably bad username
				IDMappingExtUtils.traceString("no userObj - probably bad username");
			}
		} else {
			// bad SCIM response, probably SCIM config error
			IDMappingExtUtils.traceString("bad SCIM response, probably SCIM config error");
		}
	} else {
		// no SCIM config - bad policy configuration
		IDMappingExtUtils.traceString("no SCIM config - bad policy configuration");
	}
	return result;
}

function isFIDOU2FRegisteredForUser(username) {
	var result = false;

	var scimConfig = context.get(Scope.SESSION, "urn:ibm:security:asf:policy", "scimConfig");
	if (scimConfig != null) {
		var resp = ScimClient.httpGet(scimConfig, getSCIMQueryURL(username));
		if (resp != null && resp.getCode() == 200) {
			var respJson = JSON.parse(resp.getBody());
			IDMappingExtUtils.traceString("SCIM resp: "+respJson.totalResults);
			IDMappingExtUtils.traceString("SCIM resp: "+resp.getBody());
	
			var userObj = getSCIMUserRecordFromResults(respJson);
			if (userObj != null) {
				IDMappingExtUtils.traceString("Found a user with : "+JSON.stringify(userObj));
				
				var fidoU2FData = userObj['urn:ietf:params:scim:schemas:extension:isam:1.0:U2F'];
				
				if (fidoU2FData != null) {
					var tokens = fidoU2FData["tokens"];
	
					IDMappingExtUtils.traceString("FIDO U2F tokens : "+JSON.stringify(tokens));
					
					if (tokens != null && tokens.length > 0) {
						// there is at least one registered U2F token
						result = true;	
					}
				} else {
					// no FIDO u2f data, probably not registered
					IDMappingExtUtils.traceString("no FIDO u2f data, probably not registered");
				}
			} else {
				// no userObj - probably bad username
				IDMappingExtUtils.traceString("no userObj - probably bad username");
			}
		} else {
			// bad SCIM response, probably SCIM config error
			IDMappingExtUtils.traceString("bad SCIM response, probably SCIM config error");
		}
	} else {
		// no SCIM config - bad policy configuration
		IDMappingExtUtils.traceString("no SCIM config - bad policy configuration");
	}
	return result;
}

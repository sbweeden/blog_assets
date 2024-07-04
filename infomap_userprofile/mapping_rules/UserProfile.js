importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.ibm.security.access.user.UserLookupHelper);

const userAttrNameToLDAPAttrName = {
    "email": "mail",
    "displayName": "displayName"
};

function debugLog(s) {
    IDMappingExtUtils.traceString(s);
}

function javaArrayToJSArray(javaArray) {
    var jsArray = null;
    if (javaArray != null) {
		jsArray = [];
	    for (let i = 0; i < javaArray.length; i++) {
	            jsArray.push(''+javaArray[i]);
	    }
	}
    return jsArray;
}

function getInfomapUsername() {
	// get username from already authenticated user
	let result = context.get(Scope.REQUEST,
			"urn:ibm:security:asf:request:token:attribute", "username");

	if (result != null) {
		// make it a javascript string - this prevents stringify issues later
		result = '' + result;
	}
	return result;
}

function getInfomapDisplayName() {
	// look for credential attribute displayName and use it if present
    // otherwise fallback to username
	let result = context.get(Scope.REQUEST,
			"urn:ibm:security:asf:request:token:attribute", "displayName");

    if (result == null) {
        result = getInfomapUsername();
    }

	if (result != null) {
		// make it a javascript string - this prevents stringify issues later
		result = '' + result;
	}
	return result;
}

function getUserLookupHelper() {
    let result = new UserLookupHelper();
	// use ISAM RTE - requires bind-dn and bind-pwd in ldap.conf
	result.init();

    return result;
}

function updateAttributes(attrs, username) {
    let ulh = getUserLookupHelper();
	let user = ulh.getUser(username);

    Object.keys(attrs).forEach((a) => {
        let ldapAttrName = userAttrNameToLDAPAttrName[a];
        if (ldapAttrName != null) {
            user.replaceAttribute(ldapAttrName, attrs[a]);
        } else {
            debugLog("updateAttributes skipping unknown or unsupported attribute: " + a);
        }
    });
}

function populateUserAttributes(o, username) {
    let ulh = getUserLookupHelper();
    let user = ulh.getUser(username);
    o.attributes = {};

    let debugTraceAttributeNames = false;
    if (debugTraceAttributeNames) {
        attrNames = javaArrayToJSArray(user.getAttributeNames());
        debugLog("populateUserAttributes.attrNames: " + JSON.stringify(attrNames));
        attrNames.forEach((a) => {
            debugLog("a: " + a + " val: " + user.getAttribute(a));
    
        });            
    }

    Object.keys(userAttrNameToLDAPAttrName).forEach((a) => {
        let existingValue = user.getAttribute(userAttrNameToLDAPAttrName[a]);
        if (existingValue != null && existingValue.length() > 0) {
            o.attributes[a] = ''+existingValue;
        }
    });
}

//
// Main content starts here
//

let pageJSON = {};
let username = getInfomapUsername();
let displayName = getInfomapDisplayName();
if (username != null && username != "unauthenticated") {
    pageJSON.username = username;
    pageJSON.displayName = displayName;

    // is this a post containing data to update?
    let action = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "action");
    if (action != null && action.equals("update")) {
        try {
            let profileJSONStr = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "profileJSON");
            if (profileJSONStr != null && profileJSONStr.length() > 0) {
                let profileJSON = JSON.parse(''+profileJSONStr);
                updateAttributes(profileJSON, username);
            }
        } catch(e) {
            debugLog("Caught error trying to process update: " + e);
        }
    }

    // return the current user profile attributes for display
    populateUserAttributes(pageJSON, username);

} else {
    // error - user was not authenticated
    pageJSON.error = "User not authenticated";
}

macros.put("@ESCAPED_PAGE_JSON@", JSON.stringify(pageJSON));
page.setValue("/authsvc/authenticator/infomap_userprofile/userprofile.html");

// this infomap never "logs you in"
success.setValue(false);
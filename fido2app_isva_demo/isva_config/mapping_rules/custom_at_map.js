importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.fedmgr2.trust.util.LocalSTSClient);

/**
 * This mapping rule is used to allow the username to be used as the value of an OAuth access token for testing.
 * It requires:
 *  -  A custom STS chain is set up with format STSUU(validate) -> Map(this file) -> STSUU(issue)
 *       - Name (suggested): oauth_stsuu_to_stsuu
 *       - Request type: Validate (http://schemas.xmlsoap.org/ws/2005/02/trust/Validate)
 *       - AppliesTo address: http://appliesto/customat
 *       - Issuer address: urn:ibm:ITFIM:oauth20:token:bearer
 *  -  The WebSEAL configuration file is updated so that:
 *      [tfim-cluster:oauth-cluster]
 *      default-fed-id = http://appliesto/customat
 *      
 */

//IDMappingExtUtils.traceString("STSUU at start of custom_at_map: " + stsuu.toString());

/**
 * Discover the request_type
 */
var request_type = null;

// The request type - if none available assume 'resource'
var global_temp_attr = stsuu.getContextAttributes().getAttributeValuesByNameAndType("request_type", "urn:ibm:names:ITFIM:oauth:request");
if (global_temp_attr != null && global_temp_attr.length > 0) {
	request_type = global_temp_attr[0];
} else {
	request_type = "resource";
}

if (request_type == "resource") {
	/*
	 * Treat the value of the access token as the username - very unsafe, only suitable for testing.
	 */
	var access_token = stsuu.getContextAttributes().getAttributeValueByNameAndType("access_token", "urn:ibm:names:ITFIM:oauth:param");
	
	if (access_token != null) {
		// just authenticate as the value of the access token
		IDMappingExtUtils.traceString("Authenticating as: " + access_token);
		stsuu.getContextAttributes().setAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("am-ext-user-id","urn:ibm:names:ITFIM:oauth:response:attribute", access_token));
		stsuu.getContextAttributes().setAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("oauth_token_client_id","urn:ibm:names:ITFIM:oauth:response:attribute", "fido2app"));
		stsuu.getContextAttributes().setAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("access_token","urn:ibm:names:ITFIM:oauth:response:attribute", access_token));
		stsuu.getContextAttributes().setAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("access_token_id","urn:ibm:names:ITFIM:oauth:response:metadata", access_token));
		stsuu.getContextAttributes().setAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("client_type","urn:ibm:names:ITFIM:oauth:response:attribute", "public"));
		stsuu.getContextAttributes().setAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("authorized","urn:ibm:names:ITFIM:oauth:response:decision", "TRUE"));
		stsuu.getContextAttributes().setAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("expires","urn:ibm:names:ITFIM:oauth:response:decision", "2030-01-01T00:00:00Z"));
		stsuu.getContextAttributes().setAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("scope","urn:ibm:names:ITFIM:oauth:response:attribute", ""));
	}
	
	// clear stuff we don't want to send back
	stsuu.getRequestSecurityTokenAttributeContainer().clear();
}

//IDMappingExtUtils.traceString("STSUU at end of custom_at_map: " + stsuu.toString());

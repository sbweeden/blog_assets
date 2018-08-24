importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

// this infomap is designed to be used in front of the email or SMS OTP delivery 2FA mechanisms when 
// the infomap_select_2fa mechanism has first run and then redirected to a policy containing this mechanism.

var errorPage = "/authsvc/authenticator/select_2fa/error.html";

// get the delivery attribute - this must exist (from infomap_select_2fa) or that's an error
var deliveryAttribute = IDMappingExtUtils.getSPSSessionData("deliveryAttribute");
if (deliveryAttribute != null) {
	// put into authsvc context for next mechanism
	context.set(Scope.SESSION, "urn:myns", "deliveryAttribute", deliveryAttribute);
	success.setValue(true);	
} else {
	macros.put("@ERROR@", "Required session state data not present.");
	page.setValue(errorPage);
	success.setValue(false);
}


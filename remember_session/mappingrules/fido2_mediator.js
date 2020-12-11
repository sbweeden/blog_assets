importClass(Packages.com.tivoli.am.fim.fido.mediation.FIDO2RegistrationHelper);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

/****************** Rule Helpers****************/
/*
 * Log a message to trace.log.
 *
 * Requires the trace component com.tivoli.am.fim.trustserver.sts.utilities.*=ALL to be enabled
 */
function trace(message) {
    IDMappingExtUtils.traceString("FIDO Mediation: " + message);
}

/*
 * Return an error to the FIDO client.
 */
function return_error(status, message) {
    error.put("status", status);
    error.put("message", message);
}

/*
 * Mediate an assertion options call.
 * This filters out any registrations that were not made with userVerification, since it's 
 * quite likely they won't be useable for login.
 */
function mediate_assertion_options() {
    let helper = new FIDO2RegistrationHelper();
    if (context.requestData.options.allowCredentials != null && context.requestData.options.allowCredentials.length > 0) {
        let newAllowCredentials = [];
        // only copy across credentials that were registered with UV
        for (let i = 0; i < context.requestData.options.allowCredentials.length; i++) {
            if (helper.getRegistrationByCredId(context.requestData.options.allowCredentials[i].id).wasUserVerified()) {
                newAllowCredentials.push(context.requestData.options.allowCredentials[i]);
            } else {
                IDMappingExtUtils.traceString("mediate_assertion_options filtering out non-uv credential: " +
                    context.requestData.options.allowCredentials[i].id);
            }
        }
        context.requestData.options.allowCredentials = newAllowCredentials;
    }
}

/*
 * Mediate an assertion result call.
 *  - returns an error if this authentication does not include userVerification
 */
function mediate_assertion_result() {
    if(!context.requestData.authData.uv) {
        return_error("UV_REQUIRED", "User verification must be performed when authenticating.");
    }
}

/*********************
 * Main rule processing.
 *********************/
 trace("context: " + JSON.stringify(context));
if (context.requestType == "assertion_options") {
    mediate_assertion_options();
} else if (context.requestType == "assertion_result") {
    mediate_assertion_result();
}

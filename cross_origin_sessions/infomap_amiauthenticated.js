var username = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "username");

/*
 * Now return the page 
 */
page.setValue("/authsvc/authenticator/amiauthenticated/amiauthenticated.html");
macros.put("@AUTHENTICATED@", ''+(username != null));

// we never actually perform a login with this infomap
success.setValue(false);

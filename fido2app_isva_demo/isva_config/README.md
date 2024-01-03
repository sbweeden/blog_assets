# ISVA Quick setup instructions for FIDO2App Demo

## Resources 

Use files at: https://github.com/sbweeden/blog_assets/tree/master/fido2app_isva_demo/isva_config

## Pre-requisites

- Your ISVA system should be configured with a Web Reverse Proxy that is functioning and accessible to both browsers and an iPhone. 
- A user account should exist (in my case this is `testuser`)

## Setup Instructions

- Import custom_at_map.js (type=STS) and fido2_mediator.js (type=FIDO2) mapping rules.
- Create a custom STS template and chain, set up with format STSUU(validate) -> Map(custom_at_map) -> STSUU(issue)
    - Name (suggested): oauth_stsuu_to_stsuu
    - Request type: Validate (http://schemas.xmlsoap.org/ws/2005/02/trust/Validate)
    - AppliesTo address: http://appliesto/customat
    - Issuer address: urn:ibm:ITFIM:oauth20:token:bearer
- Update WebSEAL to have configuration for OAuth (API protection only) - then re-enable `[forms]` auth to use https.
- Update WebSEAL for Authentication and Context Based Access Configuration.
- Update WebSEAL configuration to use custom access token validation:
```
        [tfim-cluster:oauth-cluster]
        default-fed-id = http://appliesto/customat
```
- Update WebSEAL configuration to enable credential viewer.
```
        [local-apps]
        cred-viewer = ivcreds
```
- Test with:
    `curl -k -H "Accept: application/json" -H "Authorization: Bearer testuser" https://www.myidp.ibm.com/ivcreds`

- Upload custom metadata file
- Create FIDO2 relying party for www.myidp.ibm.com, and configure to use the metadata file and custom mediator.

- For testing, try runtime trace string: 
```
com.tivoli.am.fim.trustserver.sts.utilities.*=all:com.tivoli.am.fim.trustserver.sts.modules.*=all:com.tivoli.am.fim.oidc.protocol.delegate.*=all:com.tivoli.am.fim.fido.*=all:com.ibm.iam.isfs.v2.*=all:com.tivoli.am.fim.authsvc.action.authenticator.fido.*=all
```

- When using the Postman collection for testing FIDO APIs, be sure to change the `Tests` script for the `WhoAmI` API to populate `'username` and `displayName` from `AZN_CRED_PRINCIPAL_NAME` instead of the values which come from the `fidointerop.securitypoc.com` test site.
- Configure the Postman environment, including updates to the environment variables.
- Try calling WhoAmI, FetchAttestationOptions, PostAttestationResult.
- Look for registration at: https://www.myidp.ibm.com/mga/sps/mga/user/mgmt/html/device/device_selection.html

- You can also use the FIDO2 App with:
Relying Party URL: https://www.myidp.ibm.com/mga/sps/fido2/<YOUR_RP_UUID>
Access token: testuser



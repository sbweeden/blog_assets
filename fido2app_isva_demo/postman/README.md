# FIDO2App client simulation APIs

This directory contains postman assets to demonstrate the same APIs used in the FIDO2App demonstration application. 

## Files included

The following files and their purpose are included:

| File | Purpose |
|------|---------|
| README.md	| This file |
| fidotools.js | This is a large file, and you should not need to change its contents. It contains a collection of open source utilities used to build data structures used in FIDO messages. The original source of the files and their copyright information is included within the fidotools.js file.  |
| fidoutils.js | Some additional utility functions that I have written to process specific FIDO2 messages. These functions are called from within pre/post test scripts in the API collection. It relies on the fidotools.js file. |
| FIDOInterop.postman_environment.json | This is the environment file that defines variables used by the APIs. Initially it points to the demonstration site fidointerop.securitypoc.com however you could modify this to point to your own ISVA server.  |
| FIDO2AppClient.postman_collection.json | The API collection. |

## ISVA configuration requirements

ISVA must be configured with the credential viewer local application configured at the `/ivcreds` URL. For more details on this application see [this blog post](https://community.ibm.com/community/user/security/blogs/shane-weeden1/2020/12/04/rip-epacjsp-2007-2020).

On the AAC/Federation runtime, configure a FIDO2 relying party and ensure it is working. You can use the [FIDO2 in less than 15 minutes](https://community.ibm.com/community/user/security/blogs/shane-weeden1/2021/06/25/fido2-in-less-than-15-minutes-with-isam-907) blog article with any recent version of ISVA to get FIDO2 up and running.

You should also have and OAuth API protection definition set up for the environment as access tokens are used by these APIs to authenticate as the end user during each API call.

WebSEAL should be configured to allow OAuth authentication (`oauth-auth`), and it should also be configured for `Authentication and context-based access` so that the `/mga` junction is set up correctly for FIDO2.

## Postman setup instructions

Create two *Globals* variables (Environment -> Globals):
  - `fidotools` with its value being the contents of the fidotools.js file
  - `fidoutils` with its value being the contents of the fidoutils.js file

Import the `FIDOInterop.postman_environment.json` as an environment and set as the current environment. 
 - If using the `fidointerop.securitypoc.com` test server, get your access token from the *Account Settings* page and set that within the environment. 
 - If using your own ISVA server, you will need to figure out an alternative way of generating and obtaining a valid access token. You will also need to update the `hostport`, `rpId` and `rpConfigID` environment variables to match that of your ISVA system.

Import the `FIDO2AppClient.postman_collection.json` file as an API collection.

## Usage instructions

You should first use the WhoAmI API which will access `/ivcreds` and retrieve user information. There are two reasons for doing this. The first is that it will test that your access token authentication is working successfully. Next, the Tests script that runs after this API sets two environment variables that are needed for subsequent FIDO calls - these are the `username` and `displayName`. As written, the `username` is extracted from the returned credential attribute `username` (you could change this to `AZN_CRED_PRINCIPAL_NAME` if necessary), and the `displayName` is sourced from the credential attribute `email`. If your ivcreds doesn't return email, change this to `AZN_CRED_PRINCIPAL_NAME` as well. This can be done in the `Tests` tab of the WhoAmI API. Make sure to inspect your environment after running this API, and ensure that `username` and `displayName` have valid values.

The next API to run is `FetchAttestationOptions`. It requires values from `username` and `displayName` in the environment to populate the JSON post body. Ensure this API runs successfully and the post-execution Test script completes as well without error.

Complete registration by running the `PostAttestationResult` API. This need only be done once - then you can run as many assertion flows as you wish. After this API completes, you should be able to check the list of FIDO2 registrations on the server and see a new registration for your user. 

Assertion flows run very much the same - first `FetchAssertionOptions` followed by `PostAssertionResult`. The `txAuthSimple` extension is included in the `PostAssertionResult` API - to modify the transaction text, update the `Pre-request Script` in the `PostAssertionResult` API. The inclusion of the `txAuthSimple` extension and its value is obvious.

If you check mediator trace at the server, you should be able to see the `txAuthSimple` transaction text in the `mediate_assertion_result` flow.

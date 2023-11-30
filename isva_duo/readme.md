# Integrating Duo Authentication into IBM Security Verify Access

On occassion IBM Security Verify Access enterprise customers may already have other multi-factor solutions in use, such as Duo Security. I recently assisted a customer by providing a skeleton solution for this using InfoMap-based authentication, and thought it might be useful to others to share that implementation.

Note that this solution and accompanying code are provided as-is, without support, but make use of standard APIs as advertised publicly in the [Duo Auth API documentation](https://duo.com/docs/authapi). That said I am happy to help our customers with questions on what has been done here, and encourage engagement via the [IBM Security Verify Discussion Forum](https://community.ibm.com/community/user/security/communities/community-home/digestviewer?communitykey=e7c36119-46d7-42f2-97a9-b44f0cc89c6d).

## Pre-requisite knowledge

This article is going to assume familiarity with IBM Security Verify Access (ISVA), and the creation and use of InfoMap authentication mechanisms and policies. There are existing assets available to learn more about InfoMap authenticaiton, including:
 - [An Introduction to the InfoMap Authentication Mechanism in ISAM 9.0.2](https://community.ibm.com/community/user/security/blogs/shane-weeden1/2016/11/29/an-introduction-to-the-infomap-authentication-mech)
 - [The IBM Verify Mobile Multifactor Authentication Cookbook](https://community.ibm.com/community/user/security/blogs/kerry-gunn1/2022/11/29/mobile-multi-factor-authentication-ibm-verify-mfa)

I am not going to cover Duo application configuration in this article, however it will be necessary for the Duo administrator to create an `Application`, and provide the resulting `Integration key`, `Secret key`, and `API hostname` for configuration in the InfoMap.

## Scenario and Assets Overview

The assets provided in the article implement an authentication mechanism that leverages the Duo Auth API to discover 2FA capabilities for a user, prompt the user for 2FA and complete the authentication process. The entire UI is controlled by the InfoMap authentication mechanism and a page template. The only interaction with Duo is via the AuthAPI. To be clear, the Duo Universal Prompt is not used in this integration.

Enrollment of a user in Duo is not explicitly covered, although if a user is not enrolled and policy is configured to allow users to be prompted to enroll, then the Duo-generated enrollment URL is made available to the user to allow them to complete enrollment.

Assets used for this integration can be found [here in my blog_assets GitHub repository](https://github.com/sbweeden/blog_assets/tree/master/isva_duo).

## Configuration

First download all the file assets from the link above you should have a collection of files like this (note that I am not listing the `images` subdirectory, which supports this readme):

```
./readme.md
./templatepages/C/static/duoauthn.js
./templatepages/C/authsvc/authenticator/duo/login.html
./templatepages/C/authsvc/authenticator/duo/login.json
./mappingrules/duoutils.js
./mappingrules/kjur.js
./mappingrules/duovars.js
./mappingrules/duoauthn.js
```

### Page templates

Upload each of the files in the `templatepages` directory to your ISVA system, under AAC -> Template Files, matching the paths shown. You can and should update the look and feel of these as needed, eventually. The provided HTML is *very* bare-bones. Due to new best practices for content security policy, which are now the default configuration for our web reverse proxy, there is no inline javascript in the `./templatepages/C/authsvc/authenticator/duo/login.html` file - this all exists in the `./templatepages/C/static/duoauthn.js` file instead.

### Mapping rules

The mapping rules should be uploaded under AAC -> Mapping Rules, following the naming convention shown in the following table. Mapping rule names are case sensitive, and do matter because some mapping rules are imported into others. All mapping rules should be imported with the Category set to InfoMap.

| Filename | Mapping Rule Name | Notes |
| kjur.js | KJUR | This is open source - the [jsrsasign](https://github.com/kjur/jsrsasign) library, and comments to that effect are included in the file. It provides the HmacSha512 implementation used to sign parameters and include in the Authorization header used in Duo API calls. You may wish to refresh this library from time to time, but note there is some custom javascript at the top of the mapping rule that I have included to allow the rule to load into ISVA as it is a restricted Javascript environment and doesn't have all the same global environment attributes as a browser or Node.JS.  |
| duovars.js | duovars | Edit this file and include your own Duo application variables for the `Integration key`, `Secret key`, and `API hostname`. There is another configuration object in this file that you might wish to fine-tune called `duoConfig`. There are comprehensive comments in the file on what the parameters are, and how they influence the authentication experience. |
| duoutils.js | duoutils | Utility functions for InfoMaps in general, plus functions to build the signature required for Duo APIs. It even includes a capability to show you (via adding debug trace) what the equivalent `curl` command would look like for an API call to Duo. I found this useful during development for testing. |
| duoauthn.js | This is the main entry point for the InfoMap authentication mechanism, and also includes functions that make the actual HTTP calls to Duo APIs. |

Be sure to deploy all pending changes after uploading the page templates and mapping rules.

### Configure the authentication mechanism

This is very straight forward for anyone that has previously set up an InfoMap authentication mechanism. The following screenshots show exactly how it is accomplished:

![duo_authn_mech](https://github.com/sbweeden/blog_assets/master/isva_duo/images/duo_authn_mech.png "Authentication Mechanism")

### Configure the authentication mechanism

Similarly, follow these steps for configuring the authentication policy:

![duo_authn_policy](https://github.com/sbweeden/blog_assets/master/isva_duo/images/duo_authn_policy.png "Authentication Policy")


## Running the flow

The policy can be triggered (assuming path-based poicyKickoffMethod) via: `https://<your_webseal>/mga/sps/authsvc/policy/duoauthn`

Of course you would normally instrument this into a step-up login flow, or an authorization policy, but the configuration for doing that is outside the scope of this article - there are other articles showing how to configure step-up authentication and use an AAC policy as the mechanism for satisfying that. In this article I will simply access the policy directly in a browser via the URL example above.

This policy is a second-factor authentication policy, and requires that you are first authenticated. Authentication may be achieved using any authentication method to the web reverse proxy including forms-based login, or another AAC policy. You can even include the UsernamePassword mechanism in the duoauthn policy prior to the InfoMap mechanism if you wish. Bottom line - make sure you are logged in as someone before you access the InfoMap mechanism or you will see an error like this:

![duo_unauthenticated_error](https://github.com/sbweeden/blog_assets/master/isva_duo/images/duo_unauthenticated_error.png "Unauthenticated error")

Next, if you are logged in but not already registered in Duo (and user enrollment is enabled in Duo), you might see an error that looks like this:

![duo_enrollment_error](https://github.com/sbweeden/blog_assets/master/isva_duo/images/duo_enrollment_error.png "Enrollment error")

You can open this URL in the browser and complete enrollment. The mechanism could of course be modified to allow this to be a hyperlink, opened in a new tab, etc, however that is just not something I implemented in the example scenario. Not hard to do though.

So now lets look at what happens if the user is enrolled, and has configured the Duo mobile application and has mobile-push capability for transaction approval. The experience will vary depending on how the `duoConfig` configuration tuning parameters are set up in the `duovars` mapping rule. These are the defaults:

```
duoConfig = {
    supportRememberedDevices: false,
    autoMode: true,
    enabledCapabilities: [ "push", "sms", "phone", "mobile_otp" ]
}
```

Provided the user has a registration suitable for auto mode (e.g. mobile push), and if `autoMode` is set to `true` as shown above, the mechanism will immediately initiate that form of authentication. On the browser you will see messages indicating that polling is taking place waiting for the transaction to be approved (or denied) on the mobile phone:

![duo_push_polling](https://github.com/sbweeden/blog_assets/master/isva_duo/images/duo_push_polling.png "Polling")

The user can approve or deny the transaction at this point, and the mechanism will either succeed or show a denied error (same if the transaction times out).

Things get a little more interesting if `autoMode` is set to `false`. In that case the users 2FA capabilities will be discovered, and a filter applied based on the setting of the `enabledCapabilities` configuration property, and the remaining options sent back to the browser for the user to select which capability they wish to use (or an error if there are no matching capabilities):

![duo_capabilities](https://github.com/sbweeden/blog_assets/master/isva_duo/images/duo_capabilities.png "Capabilities")

I am not going to enumerate the experience on all these capabilities, other than to say that each should work with the mechanism as coded. The SMS and Mobile OTP capabilities result in a prompt to the user to enter a one-time password, which is then sent back to the mechanism and validated via an API call to Duo. Push notification we have already seen, and Phone call, are very similar, and both result in a polling activity until such time as the user has approved or denied the transaction, or a timeout occurs.

## The wrap

There is quite a lot to explore by taking a look at the code provided in this authentication mechanism, particularly in how the client-side javascript in the `./templatepages/C/static/duoauthn.js` file interacts with the mechanism during polling, however that is left as an exercise for the reader who really wishes to get in and understand the detail. The overall solution could be modified in several ways, including supporting in-line enrollment, then resuming the authentication flow rather than just stopping with an error and displaying the enrollment URL. What makes sense though will depend on your existing business processes, including how users enroll in Duo today. If you are a customer of IBM Security Verify Access, and do use Duo for 2FA, I hope these assets fast-track your ability to integrate them!

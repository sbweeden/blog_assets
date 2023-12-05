# Integrating Duo Universal Prompt Authentication into IBM Security Verify Access

I recently [documented an API-based integration with Duo and IBM Security Verify Access](https://github.com/sbweeden/blog_assets/tree/master/isva_duo). This article documents a completely different style of integration using Duo for 2FA in an IBM Security Verify Access (ISVA) environment. In this case OpenID Connect is used to integrate with the [Duo Universal Prompt](https://duo.com/docs/oauthapi#overview).

Note that this solution and accompanying code are provided as-is, without support, but make use of standard APIs as advertised publicly in the [Duo OIDC Auth API - Duo Universal Prompt](https://duo.com/docs/oauthapi). That said I am happy to help our customers with questions on what has been done here, and encourage engagement via the [IBM Security Verify Discussion Forum](https://community.ibm.com/community/user/security/communities/community-home/digestviewer?communitykey=e7c36119-46d7-42f2-97a9-b44f0cc89c6d).

## Pre-requisite knowledge

This article is going to assume familiarity with IBM Security Verify Access (ISVA), and the creation and use of InfoMap authentication mechanisms and policies. There are existing assets available to learn more about InfoMap authenticaiton, including:
 - [An Introduction to the InfoMap Authentication Mechanism in ISAM 9.0.2](https://community.ibm.com/community/user/security/blogs/shane-weeden1/2016/11/29/an-introduction-to-the-infomap-authentication-mech)
 - [The IBM Verify Mobile Multifactor Authentication Cookbook](https://community.ibm.com/community/user/security/blogs/kerry-gunn1/2022/11/29/mobile-multi-factor-authentication-ibm-verify-mfa)

I am not going to cover Duo application configuration in this article, however it will be necessary for the Duo administrator to create a `Web SDK Application`, and provide the resulting `Client ID`, `Client secret`, and `API hostname` for configuration in the InfoMap.

## Scenario and Assets Overview

The assets provided in the article implement an authentication mechanism that leverages the [Duo OIDC Auth API](https://duo.com/docs/oauthapi) to redirect to Duo to prompt for 2FA and complete the authentication process. This is quite different from using an API-only approach. There are pro's and con's to each approach. One of the reasons you might want to use OIDC and the Duo Universal Prompt is that WebAuthn (registered at Duo) can be used as an authentication method. Also inline-registraiton is built in (when enabled) with the Duo Universal Prompt. The trade-off is that your website loses control of the UI when redirecting for OIDC SSO. 

Assets used for this integration can be found [here in my blog_assets GitHub repository](https://github.com/sbweeden/blog_assets/tree/master/isva_duo_universal_prompt).

## Configuration

First download all the file assets from the link above you should have a collection of files like this (note that I am not listing the `images` subdirectory, which supports this readme):

```
./readme.md
./templatepages/C/authsvc/authenticator/duo_universal_prompt/login.html
./templatepages/C/static/duoauthn_universal_prompt.js
./mappingrules/duoauthnUniversalPrompt.js
./mappingrules/kjur.js
```

### Page templates

Upload each of the files in the `templatepages` directory to your ISVA system, under AAC -> Template Files, matching the paths shown. Due to new best practices for content security policy, which are now the default configuration for our web reverse proxy, there is no inline javascript in the `./templatepages/C/authsvc/authenticator/duo_universal_prompt/login.html` file - this all exists in the `./templatepages/C/static/duoauthn_universal_prompt.js` file instead.

### Mapping rules

The mapping rules should be uploaded under AAC -> Mapping Rules, following the naming convention shown in the following table. Mapping rule names are case sensitive, and do matter because some mapping rules are imported into others. All mapping rules should be imported with the Category set to InfoMap.

| Filename | Mapping Rule Name | Notes |
| -------- | ----------------- | ----- |
| kjur.js | KJUR | This is open source - the [jsrsasign](https://github.com/kjur/jsrsasign) library, and comments to that effect are included in the file. It provides the JWT implementation used to create and validate client assertion and id_token JWTs used in the solution. You may wish to refresh this library from time to time, but note there is some custom javascript at the top of the mapping rule that I have included to allow the rule to load into ISVA as it is a restricted Javascript environment and doesn't have all the same global environment attributes as a browser or Node.JS.  |
| duoauthnUniversalPrompt.js | duoauthnUniversalPrompt | Edit this file and update values for the following variables right near the top: <br>`let duoWebSDKClientId = "YOUR_VALUE";`<br>`let duoWebSDKClientSecret = "YOUR_VALUE";`<br>`let duoAPIEndpoint = "api-XXXXXXXX.duosecurity.com";`<br>`let pointOfContact = "https://your_webseal_hostname/mga";` |

Be sure to deploy all pending changes after uploading the page templates and mapping rules.

### Configure the authentication mechanism

This is very straight forward for anyone that has previously set up an InfoMap authentication mechanism. The following screenshots show exactly how it is accomplished:

![duo_authn_mech_universal_prompt](https://github.com/sbweeden/blog_assets/blob/master/isva_duo_universal_prompt/images/duo_authn_mech_universal_prompt.png?raw=true "Authentication Mechanism")

### Configure the authentication policy

Similarly, follow these steps for configuring the authentication policy:

![duo_authn_policy_universal_prompt](https://github.com/sbweeden/blog_assets/blob/master/isva_duo_universal_prompt/images/duo_authn_policy_universal_prompt.png?raw=true "Authentication Policy")


## Running the flow

The policy can be triggered (assuming path-based poicyKickoffMethod) via: `https://<your_webseal>/mga/sps/authsvc/policy/duoUniversalPrompt`

Of course you would normally instrument this into a step-up login flow, or an authorization policy, but the configuration for doing that is outside the scope of this article - there are other articles showing how to configure step-up authentication and use an AAC policy as the mechanism for satisfying that. In this article I will simply access the policy directly in a browser via the URL example above.

This policy is a second-factor authentication policy, and requires that you are first authenticated. Authentication may be achieved using any authentication method to the web reverse proxy including forms-based login, or another AAC policy. You can even include the UsernamePassword mechanism in the duoUniversalPrompt policy prior to the InfoMap mechanism if you wish. Bottom line - make sure you are logged in as someone before you access the InfoMap mechanism or you will see an error like this:

![duo_unauthenticated_error](https://github.com/sbweeden/blog_assets/blob/master/isva_duo_universal_prompt/images/duo_unauthenticated_error.png?raw=true "Unauthenticated error")

So now lets look at what happens if the user is authenticated, enrolled in Duo, and triggers the authentication flow. In this case I have WebAuthn authentication configured for my Duo second-factor method: 

![duo_universal_prompt_login_flow](https://github.com/sbweeden/blog_assets/blob/master/isva_duo_universal_prompt/images/duo_universal_prompt_login_flow.png?raw=true "Duo Universal Prompt Login")

## The wrap

The Duo Universal Prompt is definitely an easy way to perform Duo 2FA if you are comfortable with redirecting to Duo as part of the 2FA flow. The implementation essentially implements a simple OIDC relying-party capability in an InfoMap. It is interesting how the currently-authenticated user is asserted to Duo via a signed request JWT in the authorize request.  If you are a customer of IBM Security Verify Access, and do use Duo for 2FA, I hope these assets fast-track your ability to integrate them!

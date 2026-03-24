# IBM Security Verify Access Lua HTTP Transformations

## Overview

This readme and associated assets contains a list of tips and tricks, and sample Lua transformation rules for various utilities and specific use cases in IBM Security Verify Access (ISVA). It is mostly a collection I keep for my own work with ISVA that I thought would be useful to other practitioners. No guarantees come with these assets - use them at your own risk, but for prototyping I have found them very useful.

There is an assumption made here that you are familiar with ISVA, enough to run a web reverse proxy instance, update its configuration file, use curl to make requests to it, etc.

You should also be familar with the ISVA product documentation for Lua HTTP transformation rules. For more information on this, find the product documentation here:

[Lua Transformation](https://www.ibm.com/docs/en/sva/11.0.2?topic=transformations-lua-transformation)

Finally, you should understand that if you create a new Lua HTTP transformation rule it is initially populated with a large commented section that describes all the standard Lua modules that are available for use, as well as the custom Lua modules provided by ISVA for working with requests, responses, session attributes, credential attributes and more. I find it very useful to keep a "copy" of the default rule text with the commented out section nearby whenever I'm writing a Lua HTTP transformation rule.


## Getting started - a HelloWorld example

Probably the best way to get started is to dive into an example, and to do this we'll use a transformation rule that intercepts a request to a ficticious URL, then returns a static JSON document. Imagine for example you were hosting a .well-known document such as is used for a JWKS endpoint, a discovery document for OIDC, etc. In our case though we will just make one up, to be hosted at `/.well-known/helloworld` and it will return this content:
```
{"hello":"world"}
```

There are at least two parts to configuring a transformation rule - the rule code itself, and the trigger for when it runs. The trigger can be either a WRP configuration file update, or a POP update, although it is more common to use the WRP configuration file, and that is what we will use in this example.

Upload the Lua HTTP rule code shown below (call it `hw.lua`):
```
HTTPResponse.setHeader("content-type", "application/json")
HTTPResponse.setBody('{"hello":"world"}')
HTTPResponse.setStatusCode(200)
HTTPResponse.setStatusMsg("OK")
Control.responseGenerated(true)
```

Deploy pending changes, then activate it in the web reverse proxy with the following configuration file updates:
```
[http-transformations]
hw = hw.lua

[http-transformations:hw]
request-match = request:GET /.well-known/helloworld *
```

Note that transformation rules that operate in the `request` phase execute before authorization decisions are made, so there is no need to be logged in or set an unauthenticated ACL policy on this ficticious resource. You should be able to just open a browser and access `https://webseal.com/.well-known/helloworld` and get back the static content.

## Working with JSON

When working with Web resources in transformations it is often desirable to be able to parse and produce JSON content. Whilst this can be done with string functions, its not very easy to do, and there's a much better way using the [cjson Lua module](https://luarocks.org/modules/openresty/lua-cjson). Let's take a look at how the previous example could be modified to produce the response using [Lua Tables](https://www.lua.org/pil/2.5.html) and cjson:
```
local cjson = require 'cjson'

-- Build a response JSON object as a table
local rspJSON = {}
rspJSON["hello"] = "world"

HTTPResponse.setHeader("content-type", "application/json")

-- encode the table to a JSON string
HTTPResponse.setBody(cjson.encode(rspJSON))
HTTPResponse.setStatusCode(200)
HTTPResponse.setStatusMsg("OK")
Control.responseGenerated(true)
```

There is of course a corresponding `decode` function to transform from a JSON string to a Lua data structure as well. This works for both objects and arrays and is the preferred way of working with JSON in Lua.

## Logging utilities

Whenever writing a piece of code you will want a way to trace output when debugging. I've put together a small LoggingUtils.lua module that I find useful when building transformation rules. There are only three functions:
 - `dumpAsString`: transform complex objects like tables to strings for debug printing
 - `debugLog`: A common logging function that can be modified to either use WRP tracing or the standard `print` function which will output to the WRP msg log
 - `toHexString`: transform binary strings to hex strings for debugging binary data structures

Lets take a look at the use of this in our example.

First upload the `LoggingUtils.lua` file as a HTTP transformation in the ISVA LMI, then we can use it within the `hw.lua` example:

```
local cjson = require 'cjson'
local logger = require 'LoggingUtils'

-- Build a response JSON object as a table
local rspJSON = {}
rspJSON["hello"] = "world"

logger.debugLog('The response object is: ' .. logger.dumpAsString(rspJSON))
logger.debugLog('The hex chars of hello are: ' .. logger.toHexString('hello'))

HTTPResponse.setHeader("content-type", "application/json")

-- encode the table to a JSON string
HTTPResponse.setBody(cjson.encode(rspJSON))
HTTPResponse.setStatusCode(200)
HTTPResponse.setStatusMsg("OK")
Control.responseGenerated(true)
```

If the `debugLog` method is using `print`, you can monitor the WRP msg log for debug output instead of having to enable trace. You should see:
```
The response object is: {["hello"] = world} -- The hex chars of hello are: 68656c6c6f
```

## Processing request and response bodies

This is more of a useful note than an example. I've found that if you want to read in a request or response body and parse it, the maximum number of bytes that the body can be will be govered by the WRP configuration property:

```
[server]
request-body-max-read = 32768
```
The default is 32768, so if your body size is expected to be larger (it often is) then you need to increase this if you plan to read the entire request or response body in your transformation rule.

## List of utility and example Lua modules

This section contains a list of the different Lua HTTP utility modules and example scenario transformations that I've built and their purpose.

### Utility modules

| Module | Description |
|--------|-------------|
| ber.lua | Copied from https://github.com/Firanel/lua-ber this is used as a utility library in some of my other Lua files and is included here for convenience. |
| CachedURLRetriever.lua | Used for retrieving and caching the data from a URL such as an OIDC metadata endpoint or JWKS endpoint |
| CredParser.lua | Encodes and decodes ivcreds PAC headers, using ber.lua as the ASN.1 encoder |
| CryptoLite.lua | Built predominently on top of luaossl, exposes a range of standard cryptographic capabilities such as key generation, signing/validation and encryption/decryption. |
| FormsModule.lua | Useful for working with POST requests containing form-encoded parameters. Will also parse query string parameters. |
| HTMLUtils.lua | Provides html safe encoding/decoding functions. |
| JWTUtils.lua | Provides basic JWT generation and validation capabilities, including signed and encrypted JWTs, subject to the version of IVIA you are running as some capabilities require updates to the standard luaossl library. |
| LibDeflate.lua | Copied from https://github.com/safeteeWow/LibDeflate this is used as a utility library in some of my other Lua files and is included here for convenience. |
| LoggingUtils.lua | Allows printing to WRP msg log, and stringifies complex objects such as tables. Also has a string to hex function |
| RedisHelper.lua | Primitive redis helper for WebSEAL/IAG session management. Wraps the redis luarocks module with some code that helps with detecting configuration of Redis straight from the WebSEAL/IAG configuration file. |
| STSClient.lua | Uses the HTTPClient to call the ISVA STS. Comments show configuration requirements. | 


### Example scenarios

These scenario HTTP transformation rules have either come up in the context of a customer enquiry, or a prototype that I have been working on.

| Module | Description |
|--------|-------------|
| allow_unauthenticated.lua | Demonstrates how to skip standard authorization processing on a resource and just allow access. |
| assert_username_eai.lua | A simple EAI authentication transformation that logs you in as the username provided in the query string. Definitely for demonstration purposes only! |
| default_10_0_7.lua | This is just a copy of the out-of-the-box default Lua HTTP transformation rule from ISVA 10.0.7. Useful as a reference for the comments it contains |
| certeai.lua | A sophisticated certificate authentication EAI that demonstrates how to unpack X509 certificate data and read fields from the SubjectAltName extension that can be then used as the username to login with, or added as credential attributes |
| credential_macros.lua | A response transformation that replaces some magic string macros in the response page with values from the credential. |
| echo_context.lua | This is a handy utility that just returns in a HTTP response the context it received. This can be particularly useful to capture the context from a "real request" in a runtime environment when you then want to work with the offline Lua testing tool. |
| jwks_filter_app.lua | This *response* HTTP transformation rule looks at the response body of the JWKS endpoint and filters out any entries that don't have an x5c with a DN corresponding to a known "map table" defined as a constant in this transformation rule. |
| jwks_filter_expired.lua | This *response* HTTP transformation rule parses the output of the AAC JWKS endpoint, removing entries where any of the x5c entries contain an expired certificate. |
| oidclient.lua | This transformation rule can act as a complete replacement for the built-in WebSEAL or IAG OIDC RP capability. It has some features that at the time of writing, the built-in OIDCRP does not, including: PAR support, DPoP support, and both client_secret_jwt and private_key_jwt client authentication. |
| oidcresouceserver.lua | This transformation rule can act as an authorization gateway for OAuth access tokens, as an alternative to oauth-auth. It has support for validating DPoP access tokens, which the built-in oauth-auth does not. |
| pkmspasswd.lua | This request HTTP transformation rule can be applied to the /pkmspasswd.form submission URL for the /pkmspasswd change password function of the WRP. It demonstrates how to reject an attempt to change a password when the old and new passwords are the same. You could easily imagine this integrating with external password strength checkers as well. |
| pkmsvouchfor.lua | This transformation restricts the set of target hosts for which an ECSSO (e-community single sign-on, a very old SSO technology of WebSEAL) token will be generated. |
| preserve_credential_attributes.lua | A transformation that runs at the conclusion of each authentication method that it is configured against to propagate forward a set of credential attributes during stepup operations. |
| recaptchav3_forms_login.lua | A transformation that exercises recaptchav3 (https://developers.google.com/recaptcha/docs/v3) and is particularly intended to be used on /pkmslogin.form to try and perform bot detection of a credential stuffing attack against username/password login. |
| recaptchav3.lua | A simpler and more generic exercise of recaptchav3 (https://developers.google.com/recaptcha/docs/v3) that is purely for demonstration purposes. It could be used as a base for specific risk-based integration of recaptchav3 in a transactional scenario. |
| remove_all_cookies.lua | A HTTP transformation that removes all cookies from inbound requests. I have found this useful for resources that you want to behave statelessly when the client may be preserving and using session cookies. |
| snoop.lua | A HTTP transformation that captures the request context and logs it. This is useful for debugging and testing purposes, and can be used to capture request and response information that is being sent to and from the server. |
| terminate_user_sessions_eai.lua | DO NOT USE THIS - it doesn't actually work as I expected, but I've kept it for later reference. |
| terminate_user_sessions_redis.lua | A HTTP transformation that can be used to terminate all sessions for a user when the WebSEAL or IAG is configured to use Redis for session. |
| webseal_oidc_par.lua | A HTTP transformation that can be used as an alternative kickoff URL for the built-in WebSEAL/IAG OIDC to perform pushed authorization requests (PAR). |

### Other transformations and their purposes

| Module | Description |
|--------|-------------|
| testcredparser.lua | Exercises tests on CredParser capabilities and displays the outcome in a HTML page. |
| testcryptolite.lua | Exercises tests on a bunch of the CryptoLite functions and displays the outcome in a HTML page. |
| testjwk.lua | Exercises tests specifically on the JWK capabilities of the CryptoLite module and displays the outcome in a HTML page. |
| testjwtutils.lua | Exercises tests on the JWTUtils module and displays the outcome in a HTML page. |

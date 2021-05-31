This readme explains the InfoMap example which demonstrates how a Yubikey OTP could be used as a second-factor mechanism in IBM Security Verify Access.

The example is designed to be used as a starting point and customised depending on your particular requirements.

Supported example scenarios
---------------------------

The example supports the linking of a Yubikey against a user account, and the use of a registered Yubikey for second-factor authentication.

Known Limitations
-----------------
The InfoMap is written in such a way that the same Yubikey may be registered against more than one user account as the second-factor token. You would have to modify the InfoMap if you wished to enforce single-account-per-Yubikey semantics.

This particular example does not support using a Yubikey OTP as a first-factor authentication mechanism, although it could be modified to do that if you wanted to. If you did modify it for first-factor, you would need to either enforce single-account-per-Yubikey semantics as described above, or provide an account chooser if the YubiKey was linked to more than one account.

The InfoMap doesn't do any checks during the registration of a Yubikey OTP to ensure that the user has already authenticated with an existing second-factor if one exists for the user. 
In a real deployment this should always be done to ensure that an attacker cannot just authenticate with a password then register their own Yubikey against the user's account. 
Generally speaking, it would be wise to split out the authentication and registration logic into separate policies and enforce an advanced access control policy on registration that only permits access if the user has already authenticated using a second factor, or has no registered second factor capabilities.   
Solving this chicken/egg problem is out of scope of this example readme, and will depend on what other authentication factors are available to users. 

There is no self-care management page to view/remove registered keys for a user. To implement this you would also want to prompt for (and store) a nickname during registration so the user has some human-visible string to associate with the registration rather than just the publicID of the key.


Configuration
-------------

Obtain a Yubico API client id and secret from the Yubico website: https://upgrade.yubico.com/getapikey/

Update the mappingrules/YubiOTP.js mapping rule to include your API_CLIENT_ID and API_SECRET_KEY.

Install the provided template pages, mapping rules, and certificates (in the rt_profile_key trust store). The certificates are used for SSL trust to the YubiCloud OTP verification endpoint, and these signers could change over time.

The kjur.js mapping rule should be installed using the mapping rule name "KJUR", since it is imported into the YubiOTP.js mapping rule.

Create a single InfoMap mechanism, with URN: urn:ibm:security:authentication:asf:mechanism:yubiotp that uses the YubiOTP.js mapping rule. There is no need to explicitly specify a page template when creating the InfoMap mechanism.

Create an InfoMap authentication policy that uses just this InfoMap.

I highly recommend setting the advanced configuration property sps.authService.policyKickoffMethod=path. This allows you to have ACL enforcement on the policy so that users must be authenticated via a first factor before accessing the policy.

Runtime
-------

After performing initial user authentication, both registration and authentication flows can be tested from the same policy:

https://webseal.com/mga/sps/authsvc/policy/yubiotp


References
----------

General Yubikey OTP information: https://developers.yubico.com/OTP/
Obtain an API key for accessing YubiCloud here: https://upgrade.yubico.com/getapikey/
Details of how to validate a Yubikey OTP against YubiCloud: https://developers.yubico.com/OTP/Specifications/OTP_validation_protocol.html
Design guidelines from Yubico on adding Yubikey OTP authentication: http://resources.yubico.com/53ZDUYE6/as/pvknxfcmgb2kv6bjw8pvp2k/YubiKey-Authentication-Module-Design-Guideline-v10.pdf



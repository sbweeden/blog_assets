# Overview

This IBM Security Verify Workflow is designed to solicit registration of a passkey, post-authentication.

Ostensibly it checks whether the user has logged in already with a passkey, and if not, asks them if they would like to enroll. Should they opt in, the inline MFA registration flow is used to guide the user through passkey registration.

There's a little more to it than that - here are a list of key features:
  - The user can opt out either one-time, or permanently, and localStorage is used to remember permanent decisions for future executions of the workflow. If you are trying to nudge users towards passkeys, you can disable the opt-out-permanently capability easily by simply updating the page template.
  - The workflow has logic to only be run once-per-session.
  - The workflow prefers to solicit registration of platform passkeys. It can be modified to solicit registration of *any* passkey (including hardware security keys), although that would only be appropriate if you are sure that all your users have been issued with appropriate authenticators.
  - At present, the workflow will solicit passkey registration if the user performed login with something that wasn't a FIDO platform authenticator. This includes other FIDO authenticators such as hardware security keys. That allows solicited passkey registration of the platform authenticator after either hardware security key or cross-device (hybrid) authentication flows, as well as with any non-FIDO based login. If you are using hardware security keys only, then you would want to change this, and that could be done in the `PostDiscovery` function task of the workflow.

Logically, the workflow behaves as shown in the following flowchart:

![workflow flowchart](images/passkeyreg_flowchart.png?raw=true)

# Tenant configuration pre-requisites

For this workflow to operate correctly on your tenant, the following pre-requisite configuration is required:

- Your tenant must have FIDO2 (passkey) authentication enabled for end users. Because the idea is to solicit registration of a passkey typically after a different form of login, this should be configured for the for the `Cloud Directory` identity provider as shown:

![configure fido2 for login](images/configure_fido2_for_login.png?raw=true)

- Under `Authentication` -> `Authentication factors`, inline MFA registration must be enabled. This is done using the following General multi-factor authentication setting:

![enable inline mfa enrolment](images/enable_inline_mfa_enrolment.png?raw=true)


# Installation and Configuration

Follow the steps below to create and configure assets used by the passkey registration workflow.

## Custom Branding Theme

Create a new branding theme called `passkeyreg`, using the master template but replacing the following pages under the `pages/templates` directory. You can diff the pages against the master template to understand the changes. Each also includes HTML comments in the `<head>` tag with information on what was done for customization:
```
    ./authentication/mfa/enrollment/default/enrollment_selection.html
    ./authentication/mfa/enrollment/default/enrollment_success.html
    ./authentication/mfa/enrollment/default/fido2_enrollment.html
    ./authentication/mfa/fido2/default/passwordless_fido2.html
    ./workflow/pages/default/custom_page1.html
    ./workflow/pages/default/custom_page2.html
    ./workflow/pages/default/custom_page3.html
    ./workflow/pages/default/custom_page4.html
```

In addition to the required pages above, there are other pages which might be optionally used depending on the method of integrating the workflow into normal end-user interaction with your site. These *optional* pages are:
```
    ./authentication/login/cloud_directory/password/forgot_password/default/forgot_password_success.html
    ./authentication/login/identity_source/identity_source_selection/default/combined_login_selection.html
```

You can find more details about when to use the optional pages in the sections below on workflow launch.


The following subsections give an example of how to update the page templates.

### Creating the template page zip file

In this step, download the master theme template, overwrite those pages with the customised versions of pages associated with this article, then prepare the new zip file for configuring the new theme.

![create branding zip](images/create_branding_zip.png?raw=true)

### Creating new branding theme

In this step, create a new branding theme using the `passkeyreg.zip` page templates created in the previous step:

![create branding theme](images/create_branding_theme.png?raw=true)

### Record the themeId for later use

After the theme is created, it will be assigned an id. We will need this id when configuring a redirect URL for triggering the workflow later.  You can easily discover it using your browser by navigating to the Branding theme and recovering the themeId from the URL in your browser. In this example the themeid for the `passkeyreg` theme is `504c1358-04c7-45f4-b7b6-4dde17f1211a`:

![capture theme id](images/capture_themeid2.png?raw=true)

### Update the passkeyreg.js file with the passkeyreg themeId and install it

Edit the file page template file `pages/customjs/passkeyreg.js` and look for a variable called `passkeyregThemeId` near the top of the file. Update this to contain the themeId determined in the previous section.

Add custom JS files - first using an API Client which has at least the `manageTemplates` entitlement.
Obtain an access token using this API client, for example:
```
export CLIENT_ID="xxx"
export CLIENT_SECRET="yyyy"


curl -k -v https:/tenant_url/oauth2/token -H "Accept: application/json" -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET"

export AT="your_access_token"
```

Use the access token to upload the custom JS files:
```
$ cd ~/git/blog_assets/isv_authn_flows/passkey_registration/pages/customjs/js
$ curl --request POST \
     --url https://tenant_url/v1.0/branding/registration/js \
     --header 'accept: application/json' \
     --header 'content-type: multipart/form-data' \
     --header "Authorization: Bearer $AT" \
     -F "file=@passkeyreg.js"

$ curl --request POST \
     --url https://tenant_url/v1.0/branding/registration/js \
     --header 'accept: application/json' \
     --header 'content-type: multipart/form-data' \
     --header "Authorization: Bearer $AT" \
     -F "file=@platform.min.js"

$ curl --request POST \
     --url https://tenant_url/v1.0/branding/registration/js \
     --header 'accept: application/json' \
     --header 'content-type: multipart/form-data' \
     --header "Authorization: Bearer $AT" \
     -F "file=@cbor.js"
```

This is uploaded into the default theme, and there should be no need to override it in the passkeyreg theme.



## Import and configure workflow

- Import the workflow file `passkeyregistration.bpmn` in the Flow Designer, following the instructions below:

![import workflow](images/import_workflow.png?raw=true)

- Don't forget to publish the workflow. This can (and probably should) be done later, however it must be published at some point before it will be accessible from a browser.

- Themes for page tasks are not exported in workflows. For each page task in the workflow, edit the task and set the page theme to `passkeyreg`:

![update page tasks](images/update_page_tasks.png?raw=true)

Save and publish changes to the workflow after completing this task.


# Options for launching the workflow

After the workflow is published, it can be invoked and tested by using the launch link provided in the `General` tab of the flow designer:

![launch url](images/launch_url.png?raw=true)

This is all well and good, however real users interacting with your environment will not access it this way. Instead, we desire one or more ways of invoking the workflow in the course of normal end-user interaction with the site.

Here are some different techniques, along with some considerations for when you might apply a particular option. These techniques are not mutually exclusive. You can apply any/all of them concurrently. The sample solicited passkey enrollment workflow includes a check to ensure the workflow only prompts the user at most once per session.

| Integration technique | Comments |
| --------------------- | ---------|
| Access policy         | This is a recommended method of integration for most post-authentication style workflows such as the solicited passkey registration workflow. If a workflow is **compulsory** during end-user authentication or single sign-on, then access policy integration is required, as the other integration methods mentioned here are easily bypassed. |
| Redirect from login page | The login page is modified to always redirect to your workflow unless (using a query string parameter detected with client-side javascript) the login page was launched **from** the workflow, in which case it renders the real login page. This technique is very simple to implement, but can be bypassed by the user simply by accessing the login URL directly and including the same query string parameter that the workflow sends when redirecting for login. It is useful for optional (opt-in) workflows that you want to apply to every login event, including the solicited passkey registration workflow. |
| Integration at the end of password reset | Some sites will not want to integrate solicitied passkey registration during login or single sign-on. In fact for the consumer space the [FIDO UX Guidelines](https://fidoalliance.org/ux-guidelines/) recommend not to do this, as the user is typically in the act of performing some other task, and consumer testing has shown they will generally press *Not now* or *Never* and get on with what they were trying to do. Instead it is considered a better practice to invite passkey registration during other account management operations such as resetting a password. Enterprise use cases are a little different, as enterprises can and do often require employees to take specific actions, and one of those might be compulsory passkey registration on devices that support it. |

Configuration for each of these integration patterns is explored below.

## Using an access policy to trigger the workflow

Complete the following subsections to create an access policy that will trigger the solicited passkey registration workflow on home page access:

### Create a custom directory attribute

State management for determining if the workflow has been run in this session is managed using a session API. The session attribute is set upon completion of the workflow (see the `MarkWorkflowComplete` task). A custom attribute is used to inspect this sesion state in an access policy. Create an `Advanced rule` directory attribute called `passkey_workflow_processed` with the following CEL code:
```
statements:
    - return: >
        session.Exists("passkeyreg_done").value
```

![create directory attribute 1](images/create_directory_attribute_1.png?raw=true)
![create directory attribute 2](images/create_directory_attribute_2.png?raw=true)

### Create an access policy to trigger the workflow

In the examples shown in this section, the workflow is triggered via an access policy attached to the `Home page access` of the login portal, but it could also be attached to any application single-sign on configuration. 

The Access policy to be created has two rules:
   - If the workflow has been completed already, allow
   - Default: Redirect to the workflow


The following diagram shows how to create the `Passkey Registration` access policy. Note that in the editing of the `Default rule`, we change the action to `Redirect to get additional context` and have to provide a redirect URL.

The redirect URL is a server-relative URL to redirect to the solicited passkey workflow, following the pattern `/flows/?reference=<your_workflow_name>&themeId=<your_theme_id>`.

Following on from the earlier example of how to capture your custom themeid, the redirect URL in this example is: `/flows/?reference=passkeyregistration&themeId=504c1358-04c7-45f4-b7b6-4dde17f1211a`

![create access policy 1](images/create_access_policy_1.png?raw=true)
![create access policy 2](images/create_access_policy_2.png?raw=true)
![create access policy 3](images/create_access_policy_3.png?raw=true)
![create access policy 4](images/create_access_policy_4.png?raw=true)

### Attach access policy 

Attach the `Passkey Registration` access policy to either an application single sign-on configuration, and/or as shown here, the `Home page access`:

![attach access policy](images/attach_access_policy.png?raw=true)


## Triggering the workflow from the login page

Triggering the solicited passkey registration from the login page may be useful if your intention is to quickly integrate the flow into all login events, regardless of any access policy attached to an application or the user portal. As mentioned earlier though, this can be bypassed with simple URL manipulation, so don't rely on this technique for any compulsory workflow. 

The implementation is very simple - javascript within the login page redirects to the workflow, unless a query string parameter exists in the current page URL which is what the workflow itself sets when redirecting back for login. When this is detected, the regular login page is rendered. 

You can see the implementation of this in the included `combined_login_selection.html` page. There is a `passkeyregThemeId` variable in the `passkeyreg.js` file that needs to be updated for this to work. You may wish to put the `combined_login_selection.html` page in the default theme for situations where the user visits the top-level URL of your tenant without a themeId query string parameter.

## Triggering the workflow during password reset

In order to add passkey registration to the end of a reset password operation, you first have to enable self-service password reset in your tenant. This is done as shown:

![enable password reset](images/enable_password_reset.png?raw=true)

Once that is done, utilise the included `forgot_password_success.html` page to detect if passkey capabilities are available and (when they are) include a link to solicited passkey registration workflow. There is a `passkeyregThemeId` variable in the `passkeyreg.js` file that needs to be updated for this to work.  One drawback to this particular integration is that the user will then immediately have to login again with their new password, then they will be asked again (by the workflow prompt) if they wish to register. Some creative use of a cookie or the ambientCredentials local storage object could optimise out this second prompt, and would definitely be recommended if this was your preferred method of integration.


# Runtime example

The screenshots below are taken from a runtime example where the workflow has been integrated into the portal access policy.

After accessing the end-user portal page for your tenant, and logging in with a username/password, the user is redirected to the solicited passkey registration flow. Various checks against existing session state and browser capabilities will be performed and solicited passkey registration is deemed appropriate the user will be prompted to opt-in to passkey enrollment.

![runtime1](images/runtime1.png?raw=true)
![runtime2](images/runtime2.png?raw=true)

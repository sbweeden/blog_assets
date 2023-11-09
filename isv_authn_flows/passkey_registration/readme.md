# Overview

This IBM Security Verify Workflow is designed to solicit registration of a passkey, post-authentication.

Ostensibly it checks whether the user has logged in already with a passkey, and if not, asks them if they would like to enroll. Should they opt in, the inline MFA registration flow is used to guide the user through passkey registration.

There's a little more to it than that - here are a list of key features:
  - The user can opt out either one-time, or permanently, and localStorage is used to remember permanent decisions for future executions of the workflow.
  - The workflow has logic to only be run once-per-session (cookie-based).
  - The workflow will not solicit passkey registration if the user performed FIDO login as their first factor login in the session. In future this should be fine-tuned to only skip solicited registration if the user logged in with a _platform_ passkey in the current session. That would allow solicited passkey registration after either hardware security key or cross-device (hybrid) authentication flows.

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

Create a new branding theme called `passkeyreg`, using the master template but replacing these pages under the `pages/templates` directory. You can diff the pages against the master template to understand the changes. Each also includes HTML comments in the `&lt;head&gt;`` tag with information on what was done for customization:
```
    ./authentication/login/identity_source/identity_source_selection/default/combined_login_selection.html (this page  is **optional** - see discussion on login page below)
    ./authentication/mfa/enrollment/default/enrollment_selection.html
    ./authentication/mfa/enrollment/default/enrollment_success.html
    ./authentication/mfa/enrollment/default/fido2_enrollment.html
    ./authentication/mfa/fido2/default/passwordless_fido2.html
    ./workflow/pages/default/custom_page1.html
    ./workflow/pages/default/custom_page2.html
    ./workflow/pages/default/custom_page3.html
```

The following subsections give an example of how to complete this task.

### Creating the template page zip file

In this step, download the master theme template, overwrite those pages with the customised versions of pages associated with this article, then prepare the new zip file for configuring the new theme.

![create branding zip](images/create_branding_zip.png?raw=true)

### Creating new branding theme

In this step, create a new branding theme using the `passkeyreg.zip` page templates created in the previous step:

![create branding theme](images/create_branding_theme.png?raw=true)

### Record the themeId for later use

After the theme is created, it will be assigned an id. We will need this id when configuring a redirect URL for triggering the workflow later.  You can easily discover it using your browser by navigating to the Branding theme and recovering the themeId from the URL in your browser. In this example the themeid for the `passkeyreg` theme is `504c1358-04c7-45f4-b7b6-4dde17f1211a`:

![capture theme id](images/capture_themeid2.png?raw=true)

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

This is all well and good, however real users interacting with your deployment will not access it this way. Instead, we desire one or more ways of invoking the workflow in the course of normal end-user interaction with the site.

Here are a couple of different techniques, along with some considerations for when you might apply a particular option. 

| Integration technique | Comments |
| --------------------- | ---------|
| Access policy         | This is the recommended method of integration for most post-authentication style workflows such as the solicited passkey registration workflow. If a workflow is **compulsory** during end-user authentication or single sign-on, then an access policy integration is required, as the alternatives mentioned here is easily bypassed. |
| Redirect from login page | The login page is modified to always redirect to your workflow unless (using a query string parameter detected with client-side javascript) the login page was launched **from** the workflow, in which case it renders the real login page. This technique is very simple to implement, but can be bypassed by the user simply by including the same query string parameter in the login URL that the workflow sends when redirecting for login. It is useful for optional (opt-in) workflows, including the solicited passkey registration workflow since it is not a compulsory interaction. |
| Integration at the end of change/reset password | Some sites will not want to integrate solicitied passkey registration during login or single sign-on. In fact for the consumer space the [FIDO UX Guidelines](https://fidoalliance.org/ux-guidelines/) recommend not to do this, as the user is typically in the act of performing some other task, and will generally press *Not now* or *Never* and get on with what they were trying to do. Instead it is considered a better practice to invite passkey registration during other account management operations such as changing or resetting a password. Enterprise use cases are a little different, as enterprises can and do often require employees to take specific actions, and one of those might be compulsory passkey registration on devices that support it. |

Configuration for each of these integration patterns is explored below.

## Using an access policy to trigger the workflow

Complete the following subsections to create an access policy that will trigger the solicited passkey registration workflow on home page access:

### Create a custom directory attribute

State management for determining if the workflow has been run in this session is managed using a cookie. A custom attribute is used to inspect the cookie in an access policy. Create an `Advanced rule` directory attribute called `passkey_workflow_processed` with the following CEL code:
```
statements:
    - context: retval := "false"
    - if:
        match: requestContext.getValues('cookie').exists(x, x.contains("passkeyworkflowcomplete=true"))
        block:
            - context: retval = "true"
    - return: >
        context.retval
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

Following on from the earlier example of how to capture your custom themeid, the redirect URL in this example is: `/flows/?reference=passkeyreg&themeId=504c1358-04c7-45f4-b7b6-4dde17f1211a`

![create access policy 1](images/create_access_policy_1.png?raw=true)
![create access policy 2](images/create_access_policy_2.png?raw=true)
![create access policy 3](images/create_access_policy_3.png?raw=true)
![create access policy 4](images/create_access_policy_4.png?raw=true)

### Attach access policy 

Attach the `Passkey Registration` access policy to either an application single sign-on configuration, and/or as shown here, the `Home page access`:

![attach access policy](images/attach_access_policy.png?raw=true)


## Triggering the workflow from the login page

TBD

## Triggering the workflow during change/reset password

TBD



# Invoking the workflow from other contexts

Describe how to invoke the workflow from then end of the change password flow.
Also same for password reset.

# Runtime examples

Try accessing the end-user portal page for your tenant, and logging in with a username/password:

After login, you should be redirected to the solicited passkey registration flow, where various checks against existing session state and browser capabilities will be performed. The following screen will show momentarily while client-side capabilities are discovered:


If solicited passkey registration is deemed appropriate, the user will be prompted to opt-in to passkey enrollment:


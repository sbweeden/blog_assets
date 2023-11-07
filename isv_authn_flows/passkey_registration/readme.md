# Overview

This IBM Security Verify Workflow is designed to solicit registration of a passkey, post-authentication.

Ostensibly it checks whether the user has logged in already with a passkey, and if not, asks them if they would like to enrol. Should they opt in, the inline MFA registration flow is used to guide the user through passkey registration.

There's a little more to it than that - here are a list of key features:
  - The user can opt out either one-time, or permanently, and localStorage is used to remember permanent decisions for future executions of the workflow.
  - The workflow has logic to only be run once-per-session (cookie-based).
  - The workflow will not solicit passkey registration if the user performed FIDO login as their first factor login in the session. In future this should be fine-tuned to only skip solicited registration if the user logged in with a _platform_ passkey in the current session. That would allow solicited passkey registration after either hardware security key or cross-device (hybrid) authentication flows.

Logically, the workflow behaves as shown in the following flowchart:

![workflow flowchart](images/passkeyreg_flowchart.png?raw=true)

# Installation and Configuration

Follow the steps below to create and configure assets used by the passkey registration workflow:

## Custom Branding Theme

- Create a new branding theme called `passkeyreg`, using the master template but replacing these pages under the `pages/templates` directory. You can diff the pages to understand the changes. They also include HTML comments with information on what was done for customization:
```
        ./authentication/mfa/enrollment/default/enrollment_selection.html
        ./authentication/mfa/enrollment/default/enrollment_success.html
        ./authentication/mfa/enrollment/default/fido2_enrollment.html
        ./authentication/mfa/fido2/default/passwordless_fido2.html
        ./workflow/pages/default/custom_page1.html
        ./workflow/pages/default/custom_page2.html
        ./workflow/pages/default/custom_page3.html
        ./workflow/pages/default/custom_page5.html
```

The following subsections give an example of how to complete this task.

### Creating the template page zip file

In this step, download the master theme template, overwrite those pages with the customised versions of pages associated with this article, then prepare the new zip file for configuring the new theme.

![create branding zip](images/create_branding_zip.png?raw=true)

### Creating new branding theme

In this step, create a new branding theme using the `passkeyreg.zip` page templates created in the previous step:

![create branding theme](images/create_branding_theme.png?raw=true)

### Record the themeid for later use

After the theme is created, it will be assigned an id. We will need this id when configuring a redirect URL for triggering the workflow later.  There is currently no visible way to see this id, but you can easily discover it with browser tools looking at the API calls. 

Using the network debugger in the browser, refresh the branding page and look for an API call to the themes endpoint. Inspect the response payload to discover your theme id, then copy it for later use. 

In this example the themeid for the `passkeyreg` theme is `504c1358-04c7-45f4-b7b6-4dde17f1211a`:

![capture theme id](images/capture_themeid.png?raw=true)

## Import and configure workflow

- Import the workflow file `passkeyregistration.bpmn` in the Flow Designer, following the instructions below:

![import workflow](images/import_workflow.png?raw=true)

- Don't forget to publish the workflow. This can (and probably should) be done later, however it must be published at some point before it will be accessible from a browser.

- Themes for page tasks are not exported in workflows. For each page task in the workflow, edit the task and set the page theme to `passkeyreg`:

![update page tasks](images/update_page_tasks.png?raw=true)

Save and publish changes to the workflow after completing this task.

## Create an access policy to trigger the workflow

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

This workflow is triggered via an access policy. In the examples shown in this article, the access policy was attached to the `Home page access` of the login portal, but it could also be attached to any application. 

The Access policy to be created has two rules:
   - If the workflow has been completed already, allow
   - Default: Redirect to the workflow


The following diagram shows how to create the `Passkey Registration` access policy:

![create access policy 1](images/create_access_policy_1.png?raw=true)
![create access policy 2](images/create_access_policy_2.png?raw=true)
![create access policy 3](images/create_access_policy_3.png?raw=true)
![create access policy 4](images/create_access_policy_4.png?raw=true)

### Attach access policy 

Attach the `Passkey Registration` access policy to either an application, or as shown in the article, the `Home page access`:

![attach access policy](images/attach_access_policy.png?raw=true)


# Runtime examples

TBD

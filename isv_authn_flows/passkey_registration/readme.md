**Overview**

This IBM Security Verify Workflow is designed to solicit registration of a passkey, post-authentication.

Ostensibly it checks whether the user has logged in already with a passkey, and if not, asks them if they would like to enrol. Should they opt in, the inline MFA registration flow is used to guide the user through passkey registration.

There's a little more to it than that - here are a list of key features:
  - The user can opt out "this time", or permanently, and localStorage is used to remember permanent decisions for future executions of the workflow.
  - The workflow has logic to only be run once-per-session (cookie-based).
  - The workflow will not solicit passkey registration if the user performed FIDO login as their first factor login in the session. In future this should be fine-tuned to only skip solicited registration if the user logged in with a *platform** passkey in the current session.

Logically, the workflow behaves as shown in the following flowchart:

![workflow flowchart](images/passkeyreg_flowchart.png?raw=true)

**Installation**

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

- Import the workflow file `passkeyregistration.bpmn` in the Flow Designer, following the instructions below:

- Don't forget to publish the workflow. This can (and probably should) be done later, however it must be published at some point before it will be accessible from a browser.

- Themes for page tasks are not exported in workflows. For each page task in the workflow, edit the task and set the page theme to `passkeyreg`:


- State management for determining if the workflow has been run in this session is managed using a cookie. A custom attribute is used to inspect the cookie in an access policy. Create an `Advanced rule` directory attribute called `passkey_workflow_processed` with the following CEL code:
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
- This workflow is triggered via an access policy. In the examples shown in this article, the access policy was attached to the `Home page access` of the login portal, but it could also be attached to any application. The Access policy to be created has two rules:
   - If the workflow has been completed already, allow
   - Default: Redirect to the workflow
   The following diagram shows how to create the `Passkey Registration` access policy:


- Attach the `Passkey Registration` access policy to either an application, or as shown in the article, the `Home page access`:

**Runtime examples**



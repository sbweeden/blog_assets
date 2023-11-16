# Overview

This IBM Security Verify Workflow is designed to prompt for a username first for login (identifier-first authentication), including passkey autofill authentication. Hereafter will refer to it as the `passkey IFA` workflow.

If the user authenticates with a passkey, the workflow terminates.

If the user provides a username and presses "Next", then the workflow continues. In this example workflow at this point it just prompts for username/password login, but that could easily be modified to trigger federated single sign-on, or any other follow-up authentication capability that you wish. The real purpose of this workflow is to demonstrate passkey autofill and the basics of an identifier-first login flow.

Logically, the workflow behaves as shown in the following flowchart:

![workflow flowchart](images/passkeyifa_flowchart.png?raw=true)

# Tenant configuration pre-requisites

For this workflow to operate correctly on your tenant, the following pre-requisite configuration is required:

- Your tenant should have FIDO2 (passkey) authentication enabled for end users, as that is the primary feature of this workflow. This should be configured for the for the `Cloud Directory` identity provider as shown:

![configure fido2 for login](../passkey_registration/images/configure_fido2_for_login.png?raw=true)


# Installation and Configuration

Follow the steps below to create and configure assets used by the passkey IFA workflow.

## Custom Branding Theme

Create a new branding theme called `passkeyifa`, using the master template but replacing the following pages under the `pages/templates` directory. You can diff the pages against the master template to understand the changes. Each also includes HTML comments in the `<head>` tag with information on what was done for customization:
```
    ./workflow/pages/default/custom_page1.html
```

In addition to the required pages above, there are other pages which might be optionally used for integrating the workflow into normal end-user interaction with your site. These *optional* pages are:
```
    ./authentication/login/identity_source/identity_source_selection/default/combined_login_selection.html
```

You can find more details about when to use the optional pages in the sections below on workflow launch.


The following subsections give an example of how to update the page templates.

### Creating the template page zip file

In this step, download the master theme template, overwrite those pages with the customised versions of pages associated with this article, then prepare the new zip file for configuring the new theme.

![create branding zip](images/create_branding_zip.png?raw=true)

### Creating new branding theme

In this step, create a new branding theme using the `passkeyifa.zip` page templates created in the previous step:

![create branding theme](images/create_branding_theme.png?raw=true)

## Import and configure workflow

- Import the workflow file `passkeyifa.bpmn` in the Flow Designer, following the instructions below:

![import workflow](images/import_workflow.png?raw=true)

- Don't forget to publish the workflow. This can (and probably should) be done later, however it must be published at some point before it will be accessible from a browser.

- Themes for page tasks are not exported in workflows. For each page task in the workflow, edit the task and set the page theme to `passkeyifa`:

![update page tasks](images/update_page_tasks.png?raw=true)

Save and publish changes to the workflow after completing this task.


# Launching the workflow

After the workflow is published, it can be invoked and tested by using the launch link provided in the `General` tab of the flow designer:

![launch url](images/launch_url.png?raw=true)

This is all well and good, however real users interacting with your environment will not access it this way. Instead, we need to hook it into the login process that a person would encounter in the course of normal end-user interaction with the site.

The suggestion here is to update the login page in the **default** template, so that all end-user logins would use the workflow as the preferred way to login.

To do this, update the `combined_login_selection.html` page in the **default** template, using the provided file:
```
    ./authentication/login/identity_source/identity_source_selection/default/combined_login_selection.html
```

If you take a close look at the contents of this file, you will see that we have enabled an escape route in case your workflow doesn't work properly. If you pass a magic query string parameter (`normalLogin=true`) to the login URL, the standard login page will be displayed. To do this, you would access the URL:

```
https://<your_tenant>/idaas/mtfim/sps/idaas/login?runtime=true&normalLogin=true
```

Again, you shouldn't need to do this, but its a stop-gap in case something goes wrong.

# Combining workflows

When deploying a workflow like this one, it is recommended you also consider combining it with the [solicited passkey registration workflow](../passkey_registration/) triggered by an access policy. If a user performs username/password login, then the solicited passkey registration workflow will guide them through the (opt-in) process of registering a passkey, allowing their next login to use that passkey for a safer and easier authentication experience.

# Runtime example

The screenshots below are taken from a runtime example where the workflow has been integrated into the login page as suggested above.

After accessing your tenant, the browser is redirected to the workflow, and a prompt for username is shown. In the example here, I login with a previously registered passkey.

![runtime1](images/runtime1.png?raw=true)



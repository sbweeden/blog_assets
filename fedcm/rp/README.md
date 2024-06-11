# FedCM Relying Party support for IBM Security Verify Access

This directory contains assets required to configure ISVA as a FedCM relying party.

## Use cases

The assets provided here at the time of writing permit configuration and testing of ISVA as a FedCM relying party, and have been tried with both Google as an IDP and also with another ISVA server as the IDP. With the chrome://flags/#fedcm-multi-idp flag set (as of Chrome 125), you can even test with both IDPs enabled at the same time.

The setup instructions here will focus on configuring ISVA as a FedCM RP for Google as the IDP, but it is very easy to add additional providers.

## Pre-requisite setup

Given that the instructions here will be for configuring FedCM RP with Google as the IDP, we first need to create a Google project and credentials to allow the ISVA system to act as a client. This can be done on the [Google APIs console](https://console.cloud.google.com/apis)

In my case I have a test project with OAuth 2.0 credentials. In the credential details, record the client ID value, and be sure to add an Authorized JavaScript origin for the web origin of your ISVA RP server:

![googleapis_1](readme_images/googleapis_1.png)
![googleapis_2](readme_images/googleapis_2.png)

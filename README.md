# Cloudflare-Splunk-Addon
A none-official Splunk add-on for Cloudflare

Current version - v1.0.0

This app presents two types of data inputs for you to create and get data from:
- Cloudflare audits logs.
- Cloudflare security logs.

# Installing the Cloudflare TA
To Install the Splunk add-on straight to your Splunk deployment simply follow these few simple steps:

  - Download the file named: 'TA-cloudflare-log-fetcher_1_0_0_export.tgz'.
  - follow this link to the Splunk documentation regarding installing new add-ons in various ways: https://docs.splunk.com/Documentation/AddOns/released/Overview/Installingadd-ons
  - Installing using CLI:
      1. Upload the .tgz file to your Splunk server under location: "/tmp/" ;
         On a distributed SE set-up use your Splunk Manager deployment server for this task.
      2. Unzip the .tgz file to the desited location - "tar xvzf splunk_package_name.tgz -C $SPLUNKHOME/etc/apps";
         For distributed SE use this path - "$SPLUNKHOME/etc/deployment-apps".
      3. For single instance users - 
            * you should now see your new Splunk app ready for use in your Splunk GUI.
      4. For distributed SE - 
            * navigate to your Splunk Manager deployment GUI.
            * Under 'Settings' click 'Forwarder Management'.
            * In the search box type the name of the app - 'TA-cloudflare-log-fetcher'.
            * Click 'Edit'.
            * Using the '+' button assign the app to all of your desired Splunk server classes (make sure to check 'Restart Splunkd').
            * Wait for the Splunk deployments associated with this server class to load back up, you shall now see the app available in the associated deployment's GUI.

# Data inputs set-up
The app uses a global account settings - which you can configure under the 'Configuration' tab in the app's page. 
Also there, you will find configuration for proxy server, verify SSL, and more global parameters required by the app.

For setting up an audit data input you will need your organization ID - this is provided by Cloudflare and is a secret key - the app stores it using Splunk's built-in key vault.
Same goes for setting up a security data input, which will require you a zone ID.

# Features
- The app has an index function to keep and update a check-point after every run to avoid writing duplicated Splunk events.
- Global parameters allows you to create multiple inputs with little to no effot.
- Security input uses GraphQL query to deliver a very comprehensive and rounded log infromation.

and many more...

# Contact me
In any case regarding this app - bug fixes, feature request and more; contact me through LinkedIn, Github, or via email at amitngithub23@gmail.com .

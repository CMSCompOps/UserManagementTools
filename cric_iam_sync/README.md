# IAM CRIC Sync Script

## Overview
The IAM CRIC Sync script is designed to synchronize user and group information from  CRIC  to  IAM (Identity and Access Management) system. The script is executed as a cron job in the Openshift cluster that is hosting the CMS IAM service at CERN. It ensures that user certificates and group memberships in IAM are kept up-to-date with the information from CRIC, treating CRIC as the master source.

## Cron Details

The cron runs every 3 hours and does the following:

### User management

* Syncs all CRIC users fropm the `CMS_USERS_autosynced` CRIC group to IAM. This CRIC group is always mirroring the `cms-authorized-users` CERN e-group
    * If a user doesn't yet exist in IAM (based on their CERN username) the user is created and added to the default `cms` group
    * For all users, their certificates are being updated with any new certificates found in CRIC.

* The cron job sets the expiration date of IAM users 5 days in the future. If a user is removed from CRIC, they will be disabled in IAM after 5 days. The lifecycle management of IAM will then delete the account after it has been disabled for a year.

### Group management

* CRIC groups tagged with the `iam_group` tag in CRIC are mirrored in IAM. In every run of the cron the IAM groups are wiped clean and re-populated based on CRIC information

* cms/compute/scope membership is also given to all siteadmins (members of CRIC Groups tagged with the `facility` tag)

## Technical Details

* init_oidc.sh script is run first to acquire a token from the IAM instance. A client is configured there with the necessary scopes (`iam:admin.read`, `iam:admin.write`, `scim:read` and `scim:write`)

* The deployment of the secrets and the cron is handled by Kustomize, a configuration management tool for Kubernetes and openshift. The configuration and secrets for the cron deployment are kept in the `wlcg-auth-shared-base` Gitlab repo https://gitlab.cern.ch/wlcg-iam-deployments/wlcg-auth-shared-base which requires special access.

* Currently, the cron sends it's output to an email. This process should be revised and an alarm should be sent if the cron doesn't run as expected.


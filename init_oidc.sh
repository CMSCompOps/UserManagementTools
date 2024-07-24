#!/bin/bash

if [[ -z "${OIDC_AGENT_SECRET}" ]]; then
  echo "Please provide a client secret setting the OIDC_AGENT_SECRET env variable."
  exit 0;
fi


if [[ -z "${OIDC_AGENT_ALIAS}" ]]; then
  echo "Please provide an oidc agent alias, setting the OIDC_AGENT_ALIAS env variable."
  exit 0;
fi


if [[ -z "${IAM_ENDPOINT}" ]]; then
  echo "Please provide an IAM endpoint, setting the IAM_ENDPOINT env variable."
  exit 0;
fi

eval $(oidc-agent --no-autoload);
oidc-add --pw-env=OIDC_AGENT_SECRET ${OIDC_AGENT_ALIAS};
oidc-token -s iam:admin.read -s iam:admin.write -s scim:read -s scim:write ${OIDC_AGENT_ALIAS} > token
#!/bin/bash

./init_oidc.sh
python3 sync_iam.py --update-users | s-nail -E -v -s "IAM sync" -S smtp=smtp://cernmx.cern.ch:25 -S from="wlcg.alerts@cern.ch" panos.paparrigopoulos@cern.ch 2>&1
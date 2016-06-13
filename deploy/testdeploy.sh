#!/bin/bash

set -ue

curl -X POST $(DEPLOY_URL) \
    --user $(DEPLOY_USER):$(DEPLOY_PW) \
    --data-urlencode json='{"parameter": [{"name":"action", "value":"test--deploy"}, {"name":"team", "value":"3"}]}'



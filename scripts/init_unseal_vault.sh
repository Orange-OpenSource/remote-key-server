#!/bin/sh

set -e

DOCKER_NETWORK=rks

if [ "$1" != "CI" ]; then
  DOCKER_CURL_COMMAND="docker run --network=$DOCKER_NETWORK curlimages/curl:7.66.0"
fi

INIT=$($DOCKER_CURL_COMMAND http://rks-vault:8200/v1/sys/init -X PUT -d '{"secret_shares": 1, "secret_threshold": 1}')

KEY=$(echo "$INIT"|jq -r .keys[0])
ROOT_TOKEN=$(echo "$INIT"|jq -r .root_token)
echo "$ROOT_TOKEN" > ./root_token

$DOCKER_CURL_COMMAND http://rks-vault:8200/v1/sys/unseal -X PUT -d "{\"key\": \"$KEY\"}"

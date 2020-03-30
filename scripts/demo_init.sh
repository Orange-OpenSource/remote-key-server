#!/bin/ash

set -eo pipefail

sleep 5

RKS_HOST=rks-server

INIT=$(curl -s http://rks-vault:8200/v1/sys/init -X PUT -d '{"secret_shares": 1, "secret_threshold": 1}')
echo [DEMO INIT][Vault] initialized

KEY=$(echo "$INIT"|jq -r .keys[0])
ROOT_TOKEN=$(echo "$INIT"|jq -r .root_token)
echo "$ROOT_TOKEN" > /demo/root_token

curl -s http://rks-vault:8200/v1/sys/unseal -X PUT -d "{\"key\": \"$KEY\"}"
echo [DEMO INIT][Vault] unsealed

ADMIN_TOKEN=$ROOT_TOKEN
curl -s -k https://$RKS_HOST:8080/rks/v1/init -X POST -H "X-Vault-Token: $ADMIN_TOKEN"
echo [DEMO INIT][RKS] initialized

GROUP_TOKEN=$(curl -s -k https://$RKS_HOST:8080/rks/v1/group/test -H "X-Vault-Token: $ADMIN_TOKEN"  -d '{"callbackURL": "", "oauthURL": "", "oauthClientID": "", "oauthClientSecret": ""}' -H "Content-Type: application/json" | jq -r .groupToken)
echo [DEMO INIT][RKS] test group created

curl -s -k https://$RKS_HOST:8080/rks/v1/secret/test.com \
  -X POST -H "X-Vault-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"data\": {\"certificate\": \"$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' ./certs/rks.local.pem)\", \
  \"private_key\": \"$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' ./certs/rks.local.key)\", \
  \"meta\": {\"ttl\": 10}} \
}"
echo [DEMO INIT][RKS] test.com secret created

curl -s -k https://$RKS_HOST:8080/rks/v1/group/test/secrets/test.com -H "X-Vault-Token: $ADMIN_TOKEN" -X POST
echo [DEMO INIT][RKS] test.com secret added to test group

echo "$GROUP_TOKEN" > /demo/group_token
echo [DEMO INIT] group_token written inside ./demo/group_token

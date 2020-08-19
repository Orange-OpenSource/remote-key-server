#!/bin/bash

set -euo pipefail

if [ $# -ne 1 ]
then
	echo "Missing Arguments: ./.push_certificates.sh <adminToken>"
	exit 1
fi

ADMIN_TOKEN=$1
RKS_HOST=localhost:8080

list_certs=$(cd certs;ls cert*.pem)

for secret in $list_certs
do
	echo "$secret"

  cert_name=$(echo "$secret" | cut -d "." -f 1)

	echo "$cert_name"

	cert=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' "./certs/$secret")

	echo "$cert"

	priv_key=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' "./certs/$cert_name.key")

	echo "$priv_key"

	curl -k -X POST "https://$RKS_HOST/rks/v1/secret/$cert_name" -H "X-Vault-Token: $ADMIN_TOKEN" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{\"data\":{\"certificate\":\"$cert\",\"private_key\":\"$priv_key\",\"meta\":{\"ttl\":10}}}"

	if [ $? -ne 0 ]
	then
		echo "nop"
	fi
done

#!/usr/bin/env bash
set -euo pipefail

mkdir -p ./certs/

for i in $(seq 1 1000)
do
  openssl req -new -subj "/C=FR/CN=cert$i" -x509 \
            -addext "subjectAltName = DNS:cert$i" \
            -newkey rsa:2048 -nodes -keyout "./certs/cert$i.key" -out "./certs/cert$i.pem"
done

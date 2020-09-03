#!/bin/bash

RKS_HOST_PORT=${RKS_HOST_PORT:-rks-server:8080}
GROUP_TOKEN=${GROUP_TOKEN:?must assign GROUP_TOKEN, use docker flag: -e GROUP_TOKEN=xxx}
NODE_ID=${NODE_ID:-node1}

cat >>/etc/trafficserver/plugin.config << EOF
rks.so ${RKS_HOST_PORT} ${GROUP_TOKEN} ${NODE_ID}
EOF

exec "$@"

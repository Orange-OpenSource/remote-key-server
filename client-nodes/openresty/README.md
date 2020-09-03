# Openresty based RKS client node

Build docker image:
```bash
docker build --build-arg=https_proxy=$http_proxy --build-arg=http_proxy=$http_proxy --build-arg=HTTP_PROXY=$http_proxy --build-arg=HTTPS_PROXY=$http_proxy -t rks-node-openresty .
```

Run:
```bash
docker run -p443:8443 -e RKS_GROUP_TOKEN=s.yx0vlNoAIeewaKgIv5vQLMh6 -e RKS_IP=192.168.0.2 -e RKS_PORT=8080 -e RKS_NODE_ID=1 rks-node-openresty
```

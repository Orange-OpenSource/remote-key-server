# Python based RKS client node

Build docker image:
```bash
docker build --build-arg=https_proxy=$http_proxy --build-arg=http_proxy=$http_proxy --build-arg=HTTP_PROXY=$http_proxy --build-arg=HTTPS_PROXY=$http_proxy -t rks-node-go .
```

Run:
```bash
docker run -p443:8443 rks-node-go s.yx0vlNoAIeewaKgIv5vQLMh6 1
```

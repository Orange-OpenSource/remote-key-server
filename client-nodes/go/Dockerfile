FROM golang:1.13.6-alpine AS build

WORKDIR /rks/

COPY go.mod ./go.mod
COPY go.sum ./go.sum
# Install dependencies before copying code and benefit from docker caching
RUN go mod download

COPY ./client-node.go ./client-node.go

ENV CGO_ENABLED=0
RUN go build -a -o bin/rks-client-node .


FROM alpine:3.11.2 AS runtime
LABEL name="RKS Client Node" \
      description="Remote Key Server client node implementation" \
      url="https://github.com/Orange-OpenSource/remote-key-server/client-node" \
      maintainer="glenn.feunteun@orange.com"

RUN addgroup -g 1000 -S rks && \
  adduser -u 1000 -S rks -G rks

USER rks

COPY --from=build /rks/bin/rks-client-node /usr/bin/rks-client-node
COPY ./fake.com.crt ./fake.com.crt
COPY ./fake.com.key ./fake.com.key

EXPOSE 443/tcp
ENTRYPOINT ["rks-client-node"]

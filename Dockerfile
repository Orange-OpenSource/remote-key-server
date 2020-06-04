FROM golang:1.13.6-alpine AS build

RUN apk add --no-cache git

WORKDIR /rks/

COPY go.mod ./go.mod
COPY go.sum ./go.sum
# Install dependencies before copying code and benefit from docker caching
RUN go mod download

COPY . .

ENV CGO_ENABLED=0
RUN go build -a -installsuffix cgo -o bin/rks ./cmd/remote-key-server/

FROM alpine:3.11.2 AS runtime
LABEL name="RKS Server" \
      description="Remote Key Server image" \
      url="https://github.com/Orange-OpenSource/remote-key-server" \
      maintainer="glenn.feunteun@orange.com"

RUN addgroup -g 1000 -S rks && \
  adduser -u 1000 -S rks -G rks

USER rks

#HEALTHCHECK --interval=5s --timeout=2s --retries=3 \
#  CMD wget --no-check-certificate -q -O - https://localhost:8080/healthz || exit 1

COPY --from=build /rks/bin/rks /usr/bin/rks
COPY certs ./certs/
EXPOSE 8080/tcp
ENTRYPOINT ["rks"]

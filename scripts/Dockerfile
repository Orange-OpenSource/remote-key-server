FROM curlimages/curl:7.66.0

USER root

RUN apk add --no-cache jq

COPY ./scripts/demo_init.sh /bin/demo_init.sh
COPY ./scripts/wait-for /bin/wait-for
COPY ./certs /certs/

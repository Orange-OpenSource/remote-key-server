FROM debian:10

COPY ./src /rks-plugin/src/
COPY ./include /rks-plugin/include/

RUN apt-get update && apt-get install -y trafficserver trafficserver-dev libcurl4-openssl-dev build-essential libssl-dev libbrotli-dev && \
      cd rks-plugin && tsxs -lcurl -o /usr/lib/trafficserver/modules/rks.so -I./include src/rks.cc && \
      apt-get purge --auto-remove -y build-essential trafficserver-dev

RUN mkdir -p /var/run/trafficserver && chown trafficserver /var/run/trafficserver

COPY --chown=trafficserver ./ssl /etc/trafficserver/ssl/
COPY --chown=trafficserver ./config/plugin.config /etc/trafficserver/plugin.config
COPY ./config/records.config /etc/trafficserver/records.config
COPY ./config/ssl_multicert.config /etc/trafficserver/ssl_multicert.config

EXPOSE 8080/tcp
EXPOSE 8443/tcp

COPY --chown=trafficserver ./entrypoint.sh /entrypoint.sh
USER trafficserver

ENTRYPOINT ["/entrypoint.sh"]

CMD ["traffic_server", "-T", "rks"]

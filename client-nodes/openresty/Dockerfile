FROM openresty/openresty:1.17.8.2-alpine-fat

RUN luarocks install lua-resty-http

COPY ssl /etc/nginx/ssl
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY index.html /var/www/fake.com/public/

COPY rks_handler.lua /rks_handler.lua

EXPOSE 8443

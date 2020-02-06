PACKAGE_NAME := rks
OPENAPI_SPEC := rks-openapi.yaml
NETWORK := rks # Can switch to bridge to use default docker network
RKS_IP = $(shell docker inspect rks-server | jq -r ".[].NetworkSettings.Networks.${NETWORK}.IPAddress")
HTTP_PROXY_HOST = $(shell echo ${http_proxy} | sed 's/http:\/\/\(.*\):\([0-9]*\)\//\1/g' )
HTTP_PROXY_PORT = $(shell echo ${http_proxy} | sed 's/http:\/\/\(.*\):\([0-9]*\)\//\2/g' )
SERVICES := rks-consul rks-vault rks-server mock-callback-server
SUDO = $(shell if type sudo > /dev/null; then echo sudo; else echo; fi) # Use sudo for root command if available

.DEFAULT_GOAL=help


# ----- Build and Test -----
.PHONY: dev-env
dev-env: docker-network $(addprefix start-docker-, $(SERVICES)) ## Start dockerized dev environment consisting of rks, vault, consul and mock-callback-server

.PHONY: clean-dev-env
clean-dev-env: $(addprefix clean-docker-, $(SERVICES)) ## Shutdown dev environment docker
	# Don't delete default docker bridge
	if [ "${NETWORK}" != "bridge" ]; then \
		docker network rm ${NETWORK}; \
	fi

.PHONY: test
test: tests/rksclient dev-env ## Launch rks-server tests using python rks generated client
	docker build -f ./tests/Dockerfile --build-arg=http_proxy=${http_proxy} --build-arg=https_proxy=${https_proxy} -t rks-tests ./
	docker run --network=${NETWORK} -e ROOT_TOKEN=$$(cat root_token) --add-host=rks.local:${RKS_IP} \
		rks-tests tox -e dockertest -- \
		-x -s --rks-url https://rks.local:8080 --vault-address http://rks-vault:8200 --https --admin-login admin-rks --admin-pwd 12345

.PHONY: start-docker-rks-consul
start-docker-rks-consul: docker-network clean-docker-rks-consul
	docker run --network=${NETWORK} -d --name=rks-consul -p 8500:8500 -e CONSUL_BIND_INTERFACE=eth0 consul:1.6.1

.PHONY: start-docker-rks-vault
start-docker-rks-vault: docker-network clean-docker-rks-vault
	docker run --cap-add=IPC_LOCK --network=${NETWORK} -v ${PWD}/scripts/vault_server.hcl:/etc/vault/vault_server.hcl --name=rks-vault -p 8200:8200 -e VAULT_ADDR=http://127.0.0.1:8200 -d vault:1.3.1 server -config=/etc/vault/vault_server.hcl -log-level=debug
	sleep 5
	./scripts/init_unseal_vault.sh

.PHONY: start-rks-server
start-docker-rks-server: docker-network clean-docker-rks-server
	docker build --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy} -t rks-server:dev .
	docker run --network=${NETWORK} --name=rks-server -p 8080:8080 -d rks-server:dev --vaultaddr http://rks-vault:8200 --adminLogin admin-rks --adminPwd 12345

.PHONY: start-rks-mock-callback-server
start-docker-mock-callback-server: docker-network clean-docker-mock-callback-server
	docker build -f ./tests/mock-callback-server/Dockerfile --build-arg=http_proxy=${http_proxy} --build-arg=https_proxy=${https_proxy} -t mock-callback-server:test ./tests/ > /dev/null
	docker run --network=${NETWORK} --name=mock-callback-server -p 8081:8081 -d mock-callback-server:test

clean-docker-%:
	-docker rm -f $* > /dev/null

.PHONY: docker-network
docker-network:
	@if ! docker network ls | grep ${NETWORK}; then \
		docker network create -d bridge ${NETWORK} --subnet 172.25.0.0/24; \
	fi


# ----- OpenAPI -----
.PHONY: run-openapi-webui
run-openapi-webui: ## Start Redoc Open API Web UI on port 8088 to visualize rks OpenAPI spec
	-docker rm -f redoc-api-webui
	docker run --name redoc-api-webui -d -p 8088:80 -e SPEC_URL=/spec.yaml -v ${PWD}/${OPENAPI_SPEC}:/usr/share/nginx/html/spec.yaml redocly/redoc:v2.0.0-rc.20
	@echo Web UI available at http://localhost:8088/
	-xdg-open http://localhost:8088

.PHONY: generate-rks-client
generate-rks-client: tests/rksclient ## Generate rks python client used by tests from openapi specification

tests/rksclient: rks-openapi.yaml
	@echo Remove old client
	-rm -rf tests/rksclient/
	@echo Generate new rks client using OpenAPI Generator
	docker run --rm -v ${PWD}/tests:/out -v ${PWD}/${OPENAPI_SPEC}:/api.yaml \
		-e JAVA_TOOL_OPTIONS="-Dhttp.proxyHost=${HTTP_PROXY_HOST} -Dhttp.proxyPort=${HTTP_PROXY_PORT} -Dhttp.nonProxyHosts=localhost|127.0.0.1" \
		openapitools/openapi-generator-cli:v4.0.3 \
		generate -i /api.yaml -g python --library urllib3 --additional-properties=packageName=${PACKAGE_NAME} -o /out/rksclient
	${SUDO} chown -R $$USER:$$USER tests/rksclient
	@echo Remove empty generated client tests
	-rm -rf tests/rksclient/test

.PHONY: help
help: ## Print self generated help using Makefile comments
	@echo
	@echo 'Target              	        Description'
	@echo '-------------------------------------------------'
	@awk -F ':|##' '/^[^\t].+?:.*?##/ { \
    printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF \
  }' Makefile

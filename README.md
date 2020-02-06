# Remote Key Server (RKS)
> Centralized key server for management and distribution of TLS certificates and private keys to edge servers

## What is the Remote Key Server
The Remote Key Server is a solution to store TLS certificates and private keys and give secure access to this secrets to remote nodes. 
The main use case is enabling distributed servers to serve HTTPS traffic while securing the TLS keys storage and delivery.

Here are a few selling points
- Change from a push model where private keys are provisionned on nodes to a pull model where nodes ask for the private key only when they need it
- By allowing nodes to request private keys on demand, they don't need to store it on disk and can keep it in memory
- Ease certificates updates by only having to update the certificate on the RKS. This is especially useful in the context of short lived certificates (Mostly let's encrypt for the moment but other proposals are on the way)

The **RKS** is an API wrapper around Hashicorp Vault. 
It restricts and simplifies Vault to model interactions between nodes who need access to secret TLS keys and Vault which stores it.

Vault being a big toolbox with a lot of functionalities, we decided to implement an API on top of it with higher level functionalities. 
That way we can simplify it's usage while hiding Vault intricacies like backend setup, token generation, policies.

The API revolves around *Nodes* which need access to certain certificates/keys and *Group* of Nodes which represent logical grouping of nodes with same access to secrets

## Getting started
We provide a Make target to spin up a development environment consisting of a Remote Key Server, Hashicorp Vault and Hashicorp Consul instances running in Docker

You will need Make, Docker, jq and curl installed to run the development environment

You can start the environment with:
```bash
make dev-env # Optionally add "-j4" to run targets in parallel
```
The vault root token needed for the RKS initialization is printed in the **root\_token** file

The RKS is started with the following default administration credentials: 

| User | Password |
| ------ | ------ |
| admin-rks | 12345 |

The TLS certificate used to run the RKS is available [here](./certs).

Since it is a self signed certificate you will need to disable certificate checking when you access the API.

It is done using the `-k` flag with curl

You can check that the RKS is running by issuing:
```bash
curl -k https://localhost:8080/healthz
```

## Usage
The full RKS API specification can be browsed using:
```bash
make run-openapi-webui
```

The following commands show the main functionalities of the RKS API
```bash
# Initialize the RKS using vault root token
$ curl -k -X POST https://localhost:8080/rks/v1/init -H "X-Vault-Token: $(cat root_token)" -H "Content-Type: application/json"

# Login to get an admin token
$ curl -k https://localhost:8080/rks/v1/admin/login -H "Content-Type: application/json" \
    -d '{"login": "admin-rks", "password": "12345"}'
{"adminToken":"s.O4G0w1m0Sd29NrMVLv6FVhul"}
$ export ADMIN_TOKEN=s.O4G0w1m0Sd29NrMVLv6FVhul

# Create a group named "test" without configuring node verification
$ curl -k https://localhost:8080/rks/v1/group/test -H "X-Vault-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
    -d '{"callbackURL": "", "oauthURL": "", "oauthClientID": "", "oauthClientSecret": ""}'
{"groupToken":"s.v8f6vSBoCcSCTkGl2Y9ukq1t"}
$ export GROUP_TOKEN=s.v8f6vSBoCcSCTkGl2Y9ukq1t

# Push a secret on the RKS named rks.local, use the RKS development certificate + private key
# The awk part is to convert hidden newline characters to \n
$ curl -k https://localhost:8080/rks/v1/secret/rks.local -H "X-Vault-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
    -d "{\"data\": {\
            \"certificate\": \"$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' ./certs/rks.local.pem)\",\
            \"private_key\": \"$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' ./certs/rks.local.key)\",\
            \"meta\": {\"ttl\": 10}\
        }\
    }"

# Associate rks.local secret to the test group
$ curl -k -X POST https://localhost:8080/rks/v1/group/test/secrets/rks.local -H "X-Vault-Token: $ADMIN_TOKEN" -H "Content-Type: application/json"

# Register a new node in the group "test"
$ curl -k -X POST https://localhost:8080/rks/v1/node -H "X-Vault-Token: $GROUP_TOKEN" -H "Content-Type: application/json" -H "X-LCDN-nodeId: 1"
{"nodeToken":"s.CnEyNurJEztF1xrM8gA24ntR","ttl":180}
$ export NODE_TOKEN=s.CnEyNurJEztF1xrM8gA24ntR

# Get the rks.local secret using node token
$ curl -k https://localhost:8080/rks/v1/secret/rks.local -H "X-Vault-Token: $NODE_TOKEN"
{"data":{"meta":{"ttl":10},"certificate":"-----BEGIN CERTIFICATE----- [...]"}}

# Renew node token
$ curl -k -X POST https://localhost:8080/rks/v1/auth/token/renew-self -H "X-Vault-Token: $NODE_TOKEN" -H "Content-Type: application/json"
{"nodeToken":"s.KzcudAWeA5dxCoXWLdcsymGP","ttl":180}

# Remove rks.local association to "test"
$ curl -k -X DELETE https://localhost:8080/rks/v1/group/test/secrets/rks.local -H "X-Vault-Token: $ADMIN_TOKEN"

# Try to get secret again
$ curl -k https://localhost:8080/rks/v1/secret/rks.local -H "X-Vault-Token: $NODE_TOKEN"
failed
```

## Description
The RKS is based on [Hashicorp Vault](https://github.com/hashicorp/vault) secret store. 
It wraps Vault API to manage, store and deliver TLS private keys and certificates in the context of HTTPS content delivery

It builds upon Vault to provide a simple API to:
- Manage certificate/private key pairs (Create/Read/Update/Delete)
- Manage a group of nodes and permissions to access secrets
- Manage node registration and authorization when requesting secrets

It consists of 4 sub API defined in the [OpenAPI specification](./rks-openapi.yaml):
- [Initialization](./api/initialize) to setup the RKS
- [Administration](./api/admin) for configuration operations (Group creation, secret provisionning...)
- [Node](./api/node) for node registration
- [Secret](./api/secret) for secret access by the nodes


### Concepts
The RKS is based on two concepts: nodes and group of nodes

A node is an entity requiring access to certificates and private keys in order to establish sessions with clients. 
It can be an edge server, a cache server, a load balancer...

A group of nodes represent a system like a Content Delivery Network, Edge computing sites, distributed HTTP proxies... 
All nodes in a group share the same permissions.

On creation, a group is given a **group token**. 
This **group token** has to be provisionned onto group nodes so that they can requests their **node token** to the RKS.

For a node to get it's node token, it has to make a call to the registration endpoint of the rks using the group token.
If a callback url has been configured on group creation it will be called on each node registration. 
According to the callback url HTTP return code the node will be provided a **node token** (HTTP 200) or be denied (40X, 50X)

This allows groups to control which node can register to the RKS

This simple architecture allows to configure and monitor group access to secrets and revoke entire group nodes token or individual node token in case of token compromission.

A node can access authorized secrets for his group on demand by querying the secret endpoint using its node token. 
If the node is allowed to access the secret, it is delivered along a Time To Live indicating for how long the node can keep the secret. 
When the ttl expires the node must destroy the secret and query the secret endpoint again. 
This ttl is there to avoid nodes storing secrets on disk or for a long time when it is not needed

## Links
- Project Homepage: https://github.com/Orange-OpenSource/remote-key-server
- Issue Tracker: https://github.com/Orange-OpenSource/remote-key-server/issues

## Authors
- Glenn Feunteun
- Celine Nicolas

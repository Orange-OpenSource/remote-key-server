![Remote Key Server CI](https://github.com/Orange-OpenSource/remote-key-server/workflows/Remote%20Key%20Server%20CI/badge.svg)
# Remote Key Server (RKS)
> Centralized key server for management and distribution of TLS certificates and private keys to edge servers

## Table of content
  - [What is the Remote Key Server](#what-is-the-remote-key-server)  
  - [Getting started](#getting-started)  
  - [Usage](#usage)  
  - [Links](#links)  
  - [Authors](#authors)  


## What is the Remote Key Server
The Remote Key Server is a solution to store TLS certificates and private keys and give secure access to these secrets to remote nodes.
The main use case is enabling distributed servers to serve HTTPS traffic while securing the TLS keys storage and delivery.

Here are a few selling points
- Change from a push model where private keys are provisionned on nodes to a pull model where nodes ask for the private key only when they need it  
- By allowing nodes to request private keys on demand, they don't need to store it on disk and can keep it in memory  
- Ease certificates updates by only having to update the certificate on the RKS. This is especially useful in the context of short lived certificates  

The **RKS** is an API wrapper around [Hashicorp Vault](https://github.com/hashicorp/vault) secret store.
It restricts and simplifies Vault to model interactions between servers who need access to secret TLS keys and Vault which stores them.

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

The API revolves around *Nodes* which need access to certain certificates/keys and *Group* of Nodes which represent logical grouping of nodes with same access to secrets

### Concepts
The RKS is based on two concepts: nodes and group of nodes

A node is an entity requiring access to certificates and private keys in order to establish sessions with clients.
It can be an edge server, a cache server, a load balancer...

A group of nodes represent a system like a Content Delivery Network, Edge computing sites, distributed HTTP proxies...
All nodes in a group share the same secret access permissions.

On creation, a group is given a **group token**.
This **group token** has to be provisionned onto group nodes so that they can request their **node token** to the RKS.

For a node to get it's node token, it has to make a call to the registration endpoint of the rks using the group token.
If a callback url has been configured on group creation it will be called on each node registration.
An example callback URL implementation is available in [./tests/mock-callback-server/server.py](./tests/mock-callback-server/server.py). According to the callback server response the node will be provided a **node token** (HTTP 200) or be refused (40X, 50X)

This allows groups to control which node can register to the RKS and protect against **group token** compromission by adding another layer of verification

A node can access secrets authorized for his group on demand by querying the secret endpoint using its node token.
If the node is allowed to access the secret, it is delivered along a Time To Live indicating for how long the node can keep the secret.
When the TTL expires the node **must** destroy the secret and query the secret endpoint again.
This TTL is there to avoid nodes storing secrets on disk or for a long time when it is not needed

## Getting started
### With docker image
You could get our latest rks-aio docker image on the github package registry ([see how to configure docker for use with github package](https://docs.github.com/en/packages/using-github-packages-with-your-projects-ecosystem/configuring-docker-for-use-with-github-packages))

```bash
docker pull docker.pkg.github.com/orange-opensource/remote-key-server/rks-aio:latest
docker run --volume $PWD/certs/:/data --add-host rks.local:127.0.0.1 --name rks-aio --publish 8080:8080 --interactive --tty --detach rks-aio
```
Docker rks-aio image contains a vault server in development mode(RAM storage and not secure), and a rks-server. 
It is useful to start and see functionalities of rks.

The vault root token needed for the RKS initialization in this case (rks-aio image) is simply "root".

### By cloning repository 
Another way to get started is to clone repo and simply launch:

```bash
make dev-env
```
The vault root token needed for the RKS initialization is printed in the **root\_token** file

For deployment without docker, please see [deploy documentation](./deploy/Deploy.md)

### In both cases

The RKS is started with the following default administration credentials:

| User | Password |`
| ------ | ------ |
| admin-rks | 12345 |

The TLS certificate used to run the RKS is available [here](./certs).

Since it is a self signed certificate you will need to disable certificate checking when you access the API.
This is done with the `-k` flag with curl

You can check that the RKS is running by issuing:
```bash
curl -k https://localhost:8080/healthz
```

## Usage
The full RKS API specification can be accessed using:
```bash
make run-openapi-webui
```

The following commands show the main functionalities of the RKS API

```bash
# Initialize the RKS using vault root token
$ curl -k -X POST https://localhost:8080/rks/v1/init -H "X-Vault-Token: $(cat root_token)"

# Login to get an admin token
$ curl -k https://localhost:8080/rks/v1/admin/login \
    -H "Content-Type: application/json" \
    -d '{"login": "admin-rks", "password": "12345"}'
{"adminToken":"s.O4G0w1m0Sd29NrMVLv6FVhul"}
$ export ADMIN_TOKEN=s.O4G0w1m0Sd29NrMVLv6FVhul

# Create a group named "test" without configuring node verification (callbackURL="")
$ curl -k https://localhost:8080/rks/v1/group/test \
    -H "X-Vault-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
    -d '{"callbackURL": "", "oauthURL": "", "oauthClientID": "", "oauthClientSecret": ""}'
{"groupToken":"s.v8f6vSBoCcSCTkGl2Y9ukq1t"}
$ export GROUP_TOKEN=s.v8f6vSBoCcSCTkGl2Y9ukq1t

# Push a secret on the RKS named rks.local, use the RKS development certificate + private key
# The awk command converts line returns in the PEM files to \n
$ curl -k https://localhost:8080/rks/v1/secret/rks.local \
    -H "X-Vault-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
    -d "{\"data\": {\
            \"certificate\": \"$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' ./certs/rks.local.pem)\",\
            \"private_key\": \"$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' ./certs/rks.local.key)\",\
            \"meta\": {\"ttl\": 10}\
        }\
    }"

# Associate rks.local secret to the test group
$ curl -k -X POST https://localhost:8080/rks/v1/group/test/secrets/rks.local \
    -H "X-Vault-Token: $ADMIN_TOKEN"

# Register a new node in the group "test" with 1 as node ID
$ curl -k -X POST https://localhost:8080/rks/v1/node \
    -H "X-Vault-Token: $GROUP_TOKEN" -H "X-LCDN-nodeId: 1"
{"nodeToken":"s.CnEyNurJEztF1xrM8gA24ntR","ttl":600}
$ export NODE_TOKEN=s.CnEyNurJEztF1xrM8gA24ntR

# Get the rks.local secret using node token
$ curl -k https://localhost:8080/rks/v1/secret/rks.local -H "X-Vault-Token: $NODE_TOKEN"
{"data":{"meta":{"ttl":10},"certificate":"-----BEGIN CERTIFICATE----- [...]"}}

# Renew node token
$ curl -k -X POST https://localhost:8080/rks/v1/auth/token/renew-self \
    -H "X-Vault-Token: $NODE_TOKEN"
{"nodeToken":"s.KzcudAWeA5dxCoXWLdcsymGP","ttl":600}

# Remove rks.local association to "test"
$ curl -k -X DELETE https://localhost:8080/rks/v1/group/test/secrets/rks.local \
    -H "X-Vault-Token: $ADMIN_TOKEN"

# Try to get secret again
# Now that the secret is no longer associated with the "test" group, the access is denied by the RKS
$ curl -k https://localhost:8080/rks/v1/secret/rks.local -H "X-Vault-Token: $NODE_TOKEN"
failed
```

For more information about Usage please see [rks-handguide](./docs/rks-handguide.md)

## Links
- Project Homepage: https://github.com/Orange-OpenSource/remote-key-server
- Issue Tracker: https://github.com/Orange-OpenSource/remote-key-server/issues

## Authors
- Glenn Feunteun
- Celine Nicolas
- Benoît Gaussen

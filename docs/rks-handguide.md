# Set Up Remote Key Server (RKS)
This guide will give a step by step introduction about how to set up the Remote Key Server

## Fresh Install: RKS + Vault + Consul

Please see [Deployment guide](../deploy/Deploy.md)

**Note**: 

When calling the dev-env Makefile target, this previous steps are done automatically.

```bash
make dev-env
```
The dev environment run all components(Consul,Vault,rks-server) in docker containers and set up deployed components.

# Start scenario

Once Consul and Vault are installed, initialized and unsealed(set up), you need to call the **RKS Initialization API** endpoint, to **configure vault for RKS use and create an RKS admin user**:

In the example below, you have to replace **rks_hostname:port** with the right values.  
If you used 'make dev-env' to deploy, you may use 'rks-server:8080'.  


```bash
curl -k -X POST -H "X-Vault-Token: <root_token>" https://<rks_hostname:port>/rks/v1/init
```

Notes:
- we use curl's "-k" option in our dev environment because rks-server is launched with a self-signed certificate  
- when using the dev-env Makefile target, the vault root_token will be written in a file named *root_token* at the root of the repository directory  
- you may have to adapt port number in the curl examples depending on your install (make dev-env makes rks-server available on 8080 port)  

## RKS is now ready to use  

You're now able to provision RKS with group and secrets through the RKS Administration API.  

To do this you first need to **login to the RKS API** through RKS Administration login endpoint to get an *admin token* and use it as *X-Vault-Token* in further requests.  

If you wonder where to find admin login/password, they have been passed to RKS as command line parameters when it was started.  

In our dev env, we use *admin-rks/12345* as login/password :  

```bash
curl -k -X POST "https://<rks_hostname:port>/rks/v1/admin/login" -H  "Accept: application/json" -H  "Content-Type: application/json" -d "{\"login\":\"admin-rks\",\"password\":\"12345\"}"  

{"adminToken": "<admin_token>"}  
```

**Provide RKS with some secrets**:
For example and load tests purpose we provide a shell script to generate tests certificates:

```bash
./scripts/generate_test_certificates.sh
# Ctrl-C when you have enough
```

This will generate secrets in the certs directory:

```bash
ls certs

cert10.key  cert14.pem  cert19.key  cert22.pem  cert27.key  cert30.pem  cert35.key  cert39.pem  cert43.key  cert47.pem  cert51.key  cert55.pem  cert5.key  cert9.pem
cert10.pem  cert15.key  cert19.pem  cert23.key  cert27.pem  cert31.key  cert35.pem  cert3.key   cert43.pem  cert48.key  cert51.pem  cert56.key  cert5.pem  rks_CA.pem
[...]
```

We provide another shell script to push the generated secrets in the RKS:

```bash
./scripts/push_certificates.sh <admin_token>
```

Notes:  
*admin_token* as argument, look at the script to set how the secrets are pushed.  
You may have to edit script to set RKS_HOST to your rks_hostname:port  

You can now **create a group** for all nodes which will need access to the same set of secrets.  

In the example below, the group name is *testgroup*.  
We create it with an empty *callbackURL* and related information(*oauthURL*,*oauthClientID*,*oauthClientSecret*..) to provide a simple example.  
This will allow nodes to register without any group manager checking.  

```bash
curl -k -X POST "https://<rks_hostname:port>/rks/v1/group/testgroup" -H "X-Vault-Token: <admin_token>" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{\"callbackURL\":\"\",\"oauthURL\":\"\",\"oauthClientID\":\"\",\"oauthClientSecret\":\"\"}"
{"groupToken":"<group_token>"}
```

The RKS is responsible for renewing the *group_token* automatically.  
But if you loose your *group_token*, RKS Administration API provides a *get grouptoken* endpoint to get it back.  
It also provides an *update groutoken endpoint* to create a new one in case of RKS update.  

With this *group_token*, the only thing you're able to do is registering a node.  

Now may be the time to take a look at our openapi specification (make run-openapi-webui will start an Web OpenAPI viewer) to see all available endpoints.  

Let's **associate a secret to this group**.  

For example, associate the secret named *cert8* to *testgroup*:  
```bash
curl -k -X POST "https://<rks_hostname:port>/rks/v1/group/testgroup/secrets/cert8" -H "X-Vault-Token: <admin_token>" -H  "accept: application/json" -H  "Content-Type: application/json"
```

Secret association to a group allows all group registered nodes to access the given secret.  

Let's **register one node to get a node token**, in practice this operation should be initiated by the node itself:  

```bash
curl -k -X POST "https://<rks_hostname:port>/rks/v1/node" -H"X-LCDN-nodeId: 1" -H "X-Vault-Token: <group_token>" -H  "accept: application/json" -H  "Content-Type: application/json"

{"nodeToken":"<node_token>","ttl":600}
```

Notes:  
- *group_token* is used in "X-Vault-Token" field  
- *X-LCDN-nodeId* must be a unique integer identifying the node  
- node is responsible for renewing its token before the ttl expires  

With this *node_token*, we are now able to **get secret** *cert8*:

```bash
curl -k "https://<rks_hostname:port>/rks/v1/secrets/cert8" -H "X-Vault-Token: <node_token>"

{"data":{"meta":{"ttl":10},"certificate":"-----BEGIN CERTIFICATE-----\n[...]-----END CERTIFICATE-----\n","private_key":"-----BEGIN PRIVATE KEY-----[...]-----END PRIVATE KEY-----\n"}}
```

But we can't get *cert9* since it hasn't been associated with *testgroup*:
```bash
curl -k "https://<rks_hostname:port>/rks/v1/secrets/cert9" -H "X-Vault-Token: <node_token>"

read secret: vault unauthorized
```

The node has to **renew its node token** regularly to keep it valid
```bash
curl -k "https://<rks_hostname:port>/rks/v1/auth/token/renew-self -H "X-Vault-Token: <node_token>"

{"nodeToken":"<node_token>","ttl":600}
```

The ttl in the API answer indicates how long the token will be valid.  
If it is renewed before it expires it will be valid again for a certain period of time.  
Nodes should renew their token regularly when they need access to the RKS.  
If a node is down for a long time and doesn't renew it's token, the token will expire and the node will have to register to the RKS again to get a new token.  

If you detect a suspicious node (node_token has been hacked), you are able to **revoke this node_token** using its **X-LCDN-nodeId**.  

Then node identified by this nodeId will be able to register again. If you don't want that, you have to set a callback url at group creation and make it answers "403 FORBIDDEN" when it is asked (GET) for:  
https://*callbackurl*/*nodeId*.  
  
  
  

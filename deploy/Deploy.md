# Deployment guide

This an example deployment, which is using ansible roles to deploy consul and vault.

By default, rks-server is deployed with rks.local.pem and rks.local.key, if you want to use a custom certificate, please put certificate and private key in 'roles/ansible-rks-server/files/'. 

Then you will have to set to right values in:

'./vars/vars.yml'

And set target host IP in './hosts' file (multiple hosts for a cluster)

You will also have to set ANSIBLE_SSH_USER to target host user in 'Makefile'.

Then run:

```bash
make rks-install
```
For more documentations on consul and vault ansible deployment roles, please see:

[ansible-vault](https://github.com/ansible-community/ansible-vault)  
[ansible-consul](https://github.com/ansible-community/ansible-consul)

##Set up deployed components

In commands below, please replace 'rks-vault', 'rks-server' with your target host ip.

If this is the **first** install of : Consul, Vault, RKS on this target host, 
you have to **initialize Vault**. You can do this by calling the init endpoint on vault:

```bash
curl http://rks-vault:8200/v1/sys/init -X PUT -d '{"secret_shares": 1, "secret_threshold": 1}'
{"keys":["ef8243a53feccc73001812950d9822d77975fab20beff5e3946c076bd972ae6f"],"keys_base64":["74JDpT/szHMAGBKVDZgi13l1+rIL7/XjlGwHa9lyrm8="],"root_token":"s.YXBSZBpCqwjizLekuONvzsRe"}
export KEY=ef8243a53feccc73001812950d9822d77975fab20beff5e3946c076bd972ae6f
export root_token=s.YXBSZBpCqwjizLekuONvzsRe
```
This will generate a master key used to unseal Vault.
There could be several master keys which will all be required to unseal Vault, please, see [Vault documentation](https://www.vaultproject.io/api-docs/system/init#start-initialization).
This will also generate a root_token that we will use to configure vault.

Next step is to **unseal vault**:

```bash
curl http://rks-vault:8200/v1/sys/unseal -X PUT -d "{\"key\": \"$KEY\"}"
{"type":"shamir","initialized":true,"sealed":false,"t":1,"n":1,"progress":0,"nonce":"","version":"1.3.1","migration":false,"cluster_name":"dc1","cluster_id":"16b06562-2417-935f-8edc-0155d06334c0","recovery_seal":false,"storage_type":"consul"}
```

Please see [Vault documentation](https://www.vaultproject.io/api/system/unseal.html) to unseal with several master keys.

Vault initialization is done.
You are now able to authenticate to vault with **root_token**.

Once Consul and Vault are installed, initialized and unsealed, you need to call the **RKS Initialization API** endpoint, to **configure vault for RKS use and create an RKS admin user**:

```bash
curl -k -X POST -H "X-Vault-Token: $root_token" https://rks-server/rks/v1/init

```
## What about a cluster install

Vault and Consul can be configured to run in cluster mode, that is, running several instances of each component. It is the recommended production setup because it is more resilient to failure.

For more information about a cluster installation (see [Vault documentation](https://learn.hashicorp.com/vault/getting-started/deploy)), you will need to call init on one vault node, then unseal each vault node.


##Start scenario

please see [rks-handguide](../docs/rks-handguide.md)


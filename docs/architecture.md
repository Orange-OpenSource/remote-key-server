# RKS Components

- Remote Key Server - API server
- Hashicorp Vault - Open Source secret manager
- Hashicorp Consul - Open Source database for secret storage
- rks-cli - command line administration client

# Sources

Authoritative Vault and Consul deployment resources:

- [Vault Reference Architecture][vault-reference-architecture]
- [Vault Deployment Guide][vault-deployment-guide]
- [Vault Production Hardening][vault-production-hardening]
- [Consul Reference Architecture][consul-reference-architecture]

# Network flows

| Usage                      | Source        | Destination   | Protocol           | Port     |
| ---                        | ---           | ---           | ---                | ---      |
| Group Manager Registration | Group Manager | RKS           | HTTPS              | TCP/443  |
| Client Node Registration   | Client Node   | RKS           | HTTPS              | TCP/443  |
| Client Node Validation     | RKS           | Group Manager | HTTPS              | TCP/443? |
| Client Node Secrets access | Client Node   | RKS           | HTTPS              | TCP/443  |
| RKS Vault Access           | RKS           | Vault         | HTTPS              | TCP/8200 |
| Consul Clustering          | Consul        | Consul        | RAFT               | TCP/8300 |
| Vault Clustering           | Vault         | Vault         | Request Forwarding | TCP/8201 |

# Infrastructure

RKS can run on **bare metal** / **VM** / **containers** and has no hard dependency on a specific Operating System

Our development setup starts each RKS component in a Docker container

Our ansible deployment playbooks originally deployed RKS components inside Debian LXC containers provisionned on a Proxmox cluster

RKS leverages Consul database to ensure fault tolerance. This requires 3 or more machines deployed to allow for at least one machine failure (See Architecture below)

The Hashicorp recommended Consul infrastructure consists of 5 Consul instances spread across different availability zones so that the loss of an entire availability zone doesn't put the system down.

We propose a smaller deployment footprint here tolerating the loss of 1 node but greater care must be taken depending on the use case.

# Dimensioning

## Network requests

RKS peak load dimensioning is function of the :
- Number of secrets
- Number of client nodes (web caches, load balancers, web servers)
- Secrets ttl

`nb_rks_requests per second ~= nb_secrets * nb_client_nodes / ttl`

So for 100 secrets, 100 client nodes, a secret TTL of 1h (3600s) and all services accessed from all client nodes we can expect **10 000** requests per hour => ~ 3req/s

__Bandwidth consumption__: considering a let's encrypt secret, with its fullchain certificate and a 2048 bit RSA key it would be around 6KB per secret. 6KB times 10k requests per hour leads to 60MB egress bandwidth per hour.

## Resources

RKS storage requirement is low as we store only text objects (certificates/private keys)

When 100 secrets are loaded, making a consul database snapshots result in a 1MB file. This should be done regularly to backup consul state.

Loading 100 secrets into the RKS on a single machine with 1 instance of the RKS, Vault and Consul and running ~55 req/s for 30 minutes yields the following memory usage:

![memory usage](./memory_use.png)

A cumulated memory use of ~750MB.

# Example deployment architecture diagram

Load balancing can be done via DNS or using a hardware/software load balancer.
Requests can be directed to any RKS instance available.
Vault instances will forward client request to the currently elected Vault leader.
This is not shown here to avoid cluttering the diagram.

The RKS exposes a /healthz endpoint which can be queried to determine if the instance is healthy.

Deployment is represented here on 3 "machines", virtual or bare metal. A deployment on a container orchestrator such as Kubernetes will differ.

![architecture diagram](architecture.svg)

<!--
```plantuml
@startuml

cloud "management-network"  {
  node "group-manager" as gm
  node "server-3" {
    rectangle consul as c3
    rectangle vault as v3
    rectangle "rks-server" as r3
  }
  node "server-2" {
    rectangle consul as c2
    rectangle vault as v2
    rectangle "rks-server" as r2
  }
  node "server-1" {
    rectangle consul as c1
    rectangle vault as v1
    rectangle "rks-server" as r1
  }
}

node "load-balancer" as lb

cloud "nodes-network" {
  node "client-node1" as a1
  node "client-node2" as a2
  node "client-node3" as a3
  node "client-node4" as a4
  node "client-node5" as a5
}

c1 <-> c2: replication
c1 <-> c3: replication
c2 <-> c3: replication

r1 -> v1
r2 -> v2
r3 -> v3

v1 -> c1
v2 -> c2
v3 -> c3

gm <-down-> r1: RKS setup

a1 -up-> lb: Get Secrets
lb -up-> r1: Get Secrets
a2 -up-> lb: Get Secrets
lb -up-> r2: Get Secrets
a3 -up-> lb: Get Secrets
lb -up-> r3: Get Secrets
a4 -up-> lb: Get Secrets
lb -up-> r2: Get Secrets
a5 -up-> lb: Get Secrets
lb -up-> r1: Get Secrets

@enduml
```
-->

[vault-reference-architecture]: https://learn.hashicorp.com/vault/operations/ops-reference-architecture
[vault-deployment-guide]: https://learn.hashicorp.com/vault/day-one/ops-deployment-guide
[vault-production-hardening]: https://learn.hashicorp.com/vault/day-one/production-hardening
[consul-reference-architecture]: https://learn.hashicorp.com/consul/datacenter-deploy/reference-architecture

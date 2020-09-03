# Apache Traffic Server Plugin for RKS

This plugin allows ATS to query certificates and private keys dynamically from the RKS

The plugin is called during a client TLS handshake, before the server certificate is sent to the client.

This allows to fetch the server certificate and private key corresponding to the client requested domain name (using TLS SNI: Server Name Indication)

This is a POC using libcurl for the HTTP requests and https://github.com/nlohmann/json for json parsing

> The implementation is raw and buggy as I have not written any C++ in years
> I am also not familiar with ATS development so the plugin may not be idiomatic
> For some reason, inputing a wrong group token crashes ATS
> Finally, node_token and secrets are not cached locally, so they are requested for every client request (very ineficient)

# Build and Run

A Dockerfile is provided to build an image including Apache traffic server and the compiled plugin

Build step is :
`docker build --build-arg=https_proxy=$http_proxy --build-arg=http_proxy=$http_proxy --build-arg=HTTP_PROXY=$http_proxy --build-arg=HTTPS_PROXY=$http_proxy -t rks-node-ats`

3 runtime parameters can be provided by using environment variables:
```
RKS_HOST_PORT, rks-server:8080 by default
GROUP_TOKEN, must be provided, no default
NODE_ID, node1 by default
```

To run on a rks dev-environment started using remote-key-server `make dev-env`:

`docker run -e GROUP_TOKEN=s.cpQlKDiuY538XX9oUL6g4Fcj --network=rks -p 80:8080 -p 8443:8443 rks-node-ats`

This attaches the container to the rks dev-env network which allows the plugin to call the RKS using rks-server domain name

But this requires setting up an rks instance, pushing certificates, creating a group ...

A quicker way to setup is to run the demo remote-key-server docker-compose which starts an RKS instance pre loaded with certificates and a RKS group already setup.

The docker-compose environment is started by using `docker-compose up` in the remote-key-server directory

Once the demo is started you can get the group_token from remote-key-server/demo/group_token file

You can then run:

`docker run -e GROUP_TOKEN=s.cpQlKDiuY538XX9oUL6g4Fcj --network=remote-key-server_rks-internal -p 80:8080 -p 8043:8443 rks-node-ats`

> note the 8043 port (or any other of your choosing) since the port 8443 is already taken by a container used in the demo docker-compose

> change the GROUP_TOKEN to the content of remote-key-server/demo/group_token

You can then send an HTTPS request for the test.certificate.com domain on ATS (already pushed on the RKS):

`curl https://test.certificate.com:8043 --resolve test.certificate.com:8043:127.0.0.1 -vv -k --noproxy \*`

Now check that the ats provided certificate is correctly test.certificate.com by looking for the following string in curl output:
```
* Server certificate:
* subject: C=FR; CN=test.certificate.com
```

Make sure that it is not the default ATS certificate ats.default.local

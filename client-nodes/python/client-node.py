import socket, ssl
import time
import requests
import sys
import io
import json
import tempfile
from dataclasses import dataclass

BIND_ADDRESS = "0.0.0.0"
BIND_PORT = 8443

RKS_HOST_PORT = ""
NODE_ID = "1"
GROUP_TOKEN = ""
NODE_TOKEN = None
SECRETS = {}


@dataclass
class NodeToken:
    token: str
    ttl: int
    time_accessed: float

    def expired(self):
        return (time.time() - self.time_accessed) > self.ttl


@dataclass
class Secret:
    certificate: str
    private_key: str
    ttl: int
    time_accessed: float

    def expired(self):
        return (time.time() - self.time_accessed) > self.ttl


def get_node_token():
    global NODE_TOKEN
    # Check if node token exists and if it is still valid
    if NODE_TOKEN != None:
        if not NODE_TOKEN.expired():
            print("use existing node token")
            return NODE_TOKEN
        print("node token expired, request a new one")
    else:
        print("node token not found, register for the first time")

    resp = requests.post(
        "https://" + RKS_HOST_PORT + "/rks/v1/node",
        headers={"X-Vault-Token": GROUP_TOKEN, "X-LCDN-nodeId": NODE_ID},
        verify=False,
    )
    if resp.status_code != 201:
        print("failed to get node token:", resp.text)
        return None

    out = resp.json()
    NODE_TOKEN = NodeToken(out["nodeToken"], out["ttl"], time.time())

    print("keep the node token for", NODE_TOKEN.ttl, "seconds")
    return NODE_TOKEN


def get_secret(node_token, sni):
    global SECRETS
    print("get secret for:", sni)
    try:
        secret = SECRETS[sni]
        if not SECRETS[sni].expired():
            print("serving cached secret")
            return SECRETS[sni]
        print("secret expired, fetch from remote-key-server")
    except KeyError:
        print("secret not found in cache, fetch from remote-key-server")
        pass

    resp = requests.get(
        "https://" + RKS_HOST_PORT + "/rks/v1/secret/" + sni,
        headers={"X-Vault-Token": node_token.token},
        verify=False,
    )
    if resp.status_code != 200:
        print("failed to get secret:", resp.text)
        return None

    out = resp.json()
    SECRETS[sni] = Secret(
        out["data"]["certificate"],
        out["data"]["private_key"],
        int(out["data"]["meta"]["ttl"]),
        time.time(),
    )
    print("storing", sni, "secret for", SECRETS[sni].ttl, "seconds")
    return SECRETS[sni]


def sni_callback(socket, sni, ssl_context):
    """
    This function is called when the server receive TLS handshake CLIENT HELLO
    This is before the server sends its certificate
    We use the server name indication variable to fetch certificate and private key associated with it from the remote-key-server
    We then load the cert and private key in the ssl context so that they are used with the client
    """
    node_token = get_node_token()
    if not node_token:
        return ssl.ALERT_DESCRIPTION_HANDSHAKE_FAILURE

    secret = get_secret(node_token, sni)
    if not secret:
        return ssl.ALERT_DESCRIPTION_HANDSHAKE_FAILURE

    # load_cert_chain requires real named files
    # we can't pass certificate and private_key as variable
    # So we create 2 temporary files, write data and pass them to the function
    # THIS IS NOT SECURE, PRIVATE KEY WILL BE WRITTEN TO /tmp
    cert = tempfile.NamedTemporaryFile()
    pkey = tempfile.NamedTemporaryFile()
    cert.write(secret.certificate.encode())
    pkey.write(secret.private_key.encode())
    cert.flush()
    pkey.flush()

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert.name, keyfile=pkey.name)
    socket.context = context
    return None


def handle_client(connstream):
    data = connstream.recv(1024)
    # empty data means the client is finished with us
    if data:
        print(data)
    connstream.send(b"HTTP/1.1 200 OK\n\nhello world")
    # finished with client


def main():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    # Load default cert/private key
    context.load_cert_chain(certfile="./ssl/fake.com.crt", keyfile="./ssl/fake.com.key")
    # Call sni_callback on TLS CLIENT HELLO
    context.set_servername_callback(sni_callback)

    bindsocket = socket.socket()
    bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsocket.bind((BIND_ADDRESS, BIND_PORT))
    bindsocket.listen(5)

    while True:
        newsocket, fromaddr = bindsocket.accept()
        connstream = context.wrap_socket(newsocket, server_side=True)
        try:
            handle_client(connstream)
        finally:
            connstream.shutdown(socket.SHUT_RDWR)
            connstream.close()


if __name__ == "__main__":
    try:
        RKS_HOST_PORT = sys.argv[1]
        GROUP_TOKEN = sys.argv[2]
        NODE_ID = sys.argv[3]
    except IndexError:
        print("Missing Argument\nUsage:\n" + sys.argv[0] + " {GROUP_TOKEN} {NODE_ID}")
        sys.exit(1)

    main()

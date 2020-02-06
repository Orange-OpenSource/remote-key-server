from flask import Flask, request
from flask_httpauth import HTTPTokenAuth

app = Flask(__name__)

allowedNodes = {}
secretStores = {}
secret = {}
resp_token = {}

auth = HTTPTokenAuth("Bearer")


@auth.verify_token
def verify_token(token):
    if token is not None:
        return True
    return False


@app.route("/")
def hello_world():
    return "Hello, World!"


@app.route("/callback/nodes", methods=["GET"])
def get_allowedNodes():
    return allowedNodes, 200


@app.route("/callback/nodes/<nodeid>", methods=["GET"])
@auth.login_required
def get_allowedNode(nodeid):
    if nodeid in allowedNodes:
        return allowedNodes[nodeid], 200
    return "", 403


@app.route("/callback/nodes/<nodeid>", methods=["POST", "PUT"])
def set_allowedNode(nodeid):
    if nodeid != None:
        allowedNodes[nodeid] = {"entityId": int(nodeid)}
        return allowedNodes[nodeid], 201
    return "", 403


@app.route("/callback/nodes/<nodeid>", methods=["DELETE"])
def delete_allowedNode(nodeid):
    if nodeid != None:
        print("Delete node: " + nodeid)
        del allowedNodes[nodeid]
        return "", 204
    return "", 403


@app.route("/api/identity/oauth/token", methods=["POST"])
def get_token():
    client_id = request.args.get("client_id")
    client_secret = request.args.get("client_secret")

    user = request.authorization["username"]
    pwd = request.authorization["password"]

    # only authorise one user to test unauthorized request

    if (client_id == user and pwd == client_secret) and (
        user == "f146c93f-00af-42a2-9667-8c0d99b37953"
    ):

        resp_token[
            "access_token"
        ] = "eyJhbGciOiJSUzI1NiJ9.ewogICJzY29wZSIgOiBbICJzZWNyZXQtbWFuYWdlbWVudC5hZG1pbiIsICJpbmZyYXN0cnVjdHVyZS5yZWFkIiBdLAogICJqdGkiIDogImQ1MTI2MTc5LWY3YzctNDc0ZC1iYzBmLTY1ZjAxMTkxZTAxOCIsCiAgImNsaWVudF9pZCIgOiAiZjE0NmM5M2YtMDBhZi00MmEyLTk2NjctOGMwZDk5YjM3OTUzIiwKICAiZ3JhbnRfdHlwZSIgOiAiY2xpZW50X2NyZWRlbnRpYWxzIiwKICAiZXhwIiA6IDE1NTgwMzc2NTcsCiAgImlhdCIgOiAxNTU4MDM0MDU3LAogICJpc3MiIDogImxjZG4vb2F1dGgvdG9rZW4iLAogICJsY2RuLmtleUlkIiA6IDEKfQ.AcW69PuDpuX8AGet8id9p0mgfGDXBlm9D9xrLVkOQ3bj5eZLp_Fk1n_Zze_a2Ks6DFQkQ2X6IEdRKIvLMte67kJxG9G2loGnKIoJM9b0UmQ4RAaJ_An2yhJgMFmJlzaJ8mvdz4JKRwCxtqaMH3MBofjzNafawd43l2kuC-UB8P2wq7f0mxBkmxsdg6Wux8LwBOHLPLVyBjpIOspcfod_sWPSPXzU-ldZiqMjxnTOPSGC1qGhdEsTxfujtK-roTwlyZe8p1LTSbMgJHeQzFRMDXu_XxEE7fHwxhqJo-SdWG8cdJ2izcToP9LAsJc4ej9UUreC6VjzRJ4tgs5zVhfHjw"
        resp_token["token_type"] = "bearer"
        resp_token["expires_in"] = 3599
        resp_token["jti"] = "d5126179-f7c7-474d-bc0f-65f01191e018"

        return resp_token, 200

    return "", 401


if __name__ == "__main__":
    app.run(
        ssl_context=("/cert/server.pem", "/cert/server.pem"),
        host="0.0.0.0",
        port=8081,
        debug=True,
    )

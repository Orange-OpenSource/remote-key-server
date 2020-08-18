import random
from locust import HttpUser, task, SequentialTaskSet, constant
import requests
from pathlib import Path
import warnings
import time
import uuid


warnings.filterwarnings(
    "ignore", category=requests.urllib3.exceptions.InsecureRequestWarning
)


class AssociateThenGetSecret(SequentialTaskSet):
    @task
    def associate_secret(self):
        global SECRET_LIST
        global GROUP_NAME
        global ADMIN_TOKEN
        global RESCHEDULE_SECRET
        if RESCHEDULE_SECRET:
            self.current_secret = RESCHEDULE_SECRET
            RESCHEDULE_SECRET = None
        else:
            self.current_secret = SECRET_LIST[random.randint(0, len(SECRET_LIST) - 1)]
        with self.client.post(
            f"/rks/v1/group/{GROUP_NAME}/secrets/{self.current_secret}",
            headers={"X-Vault-Token": ADMIN_TOKEN,},
            verify=False,
            catch_response=True,
        ) as response:
            if response.status_code == 409:
                response.success()
            if response.status_code == 423:
                RESCHEDULE_SECRET = self.current_secret
                response.success()
                self.schedule_task(
                    task_callable=self.associate_secret, first=True,
                )

    @task
    def get_secret(self):
        with self.client.get(
            f"/rks/v1/secret/{self.current_secret}",
            headers={"X-Vault-Token": self.parent.node_token,},
            verify=False,
            catch_response=True,
        ) as response:
            if response.status_code == 403:
                # We have a possible race condition
                # where the get secret happens before the group policy update has been called in the associate secret function
                # So we check a second time after waiting a bit to see if secret access is still not ok
                response.success()

                time.sleep(0.01)
                response = self.client.get(
                    f"/rks/v1/secret/{self.current_secret}",
                    headers={"X-Vault-Token": self.parent.node_token,},
                    verify=False,
                )
                if response.status_code == 403:
                    print("get secret error request headers:", response.headers)


class ClientNode(HttpUser):
    wait_time = constant(0)
    node_id = ""
    node_token = ""
    current_secret = ""
    tasks = {AssociateThenGetSecret}

    def on_start(self):
        global GROUP_TOKEN
        self.node_id = str(uuid.uuid4())
        response = self.client.post(
            "/rks/v1/node",
            headers={"X-LCDN-nodeId": self.node_id, "X-Vault-Token": GROUP_TOKEN,},
            verify=False,
        )
        self.node_token = response.json()["nodeToken"]
        print("registered node, X-Vault-Token: ", self.node_token)

    #    @task(1)
    #    def renew_token(self):
    #        response = self.client.post(
    #            "/rks/v1/auth/token/renew-self",
    #            headers={"X-Vault-Token": self.node_token,},
    #            verify=False,
    #        )


def init_rks(root_token_file_path: str) -> None:
    root_token = open(root_token_file_path).read().strip("\n")
    response = requests.post(
        "https://localhost:8080/rks/v1/init",
        headers={"X-Vault-Token": root_token},
        verify=False,
    )


def get_admin_token() -> str:
    response = requests.post(
        "https://localhost:8080/rks/v1/admin/login",
        json={"login": "admin-rks", "password": "12345"},
        verify=False,
    )
    return response.json()["adminToken"]


def create_group(admin_token: str):
    group_name = uuid.uuid4()  # Generate random group name
    response = requests.post(
        f"https://localhost:8080/rks/v1/group/{group_name}",
        headers={"X-Vault-Token": admin_token},
        json={
            "callbackURL": "",
            "oauthURL": "",
            "oauthClientID": "",
            "oauthClientSecret": "",
        },
        verify=False,
    )
    return group_name, response.json()["groupToken"]


def push_all_secrets(admin_token: str, cert_directory: str) -> None:
    secret_list = []
    p = Path("../certs")
    for path in p.glob("*.pem"):
        secret_name = path.stem
        cert = path.open().read()
        try:
            key = Path("../certs/" + secret_name + ".key").open().read()
        except FileNotFoundError as exc:
            # Certificate has no corresponding private key (rks_CA.pem for example)
            print(exc)
            continue

        response = requests.post(
            f"https://localhost:8080/rks/v1/secret/{secret_name}",
            headers={"X-Vault-Token": admin_token},
            json={
                "data": {"certificate": cert, "private_key": key, "meta": {"ttl": 10}}
            },
            verify=False,
        )
        response.raise_for_status()
        print(f"pushed {secret_name}")
        secret_list.append(secret_name)

    return secret_list


# I don't know how to pass parameters to the User classes
# so global variables are used
init_rks("../root_token")
ADMIN_TOKEN = get_admin_token()
GROUP_NAME, GROUP_TOKEN = create_group(ADMIN_TOKEN)
SECRET_LIST = push_all_secrets(ADMIN_TOKEN, "../certs")
RESCHEDULE_SECRET = None

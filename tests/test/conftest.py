# Software Name : Remote Key Server
# Version: 0.9.0
# SPDX-FileCopyrightText: Copyright (c) 2020 Orange
# SPDX-License-Identifier: MPL-2.0
#
# This software is distributed under the Mozilla Public License 2.0,
# the text of which is available at https://www.mozilla.org/en-US/MPL/2.0/
# or see the "LICENSE" file for more details.
#
# Author: Glenn Feunteun, Celine Nicolas
import os
import pytest
import rks
import requests
import json
import copy
import warnings
from rks.api.rks_initialization_api import RKSInitializationApi
from rks.api.rks_administration_api import RKSAdministrationApi
from rks.api.rks_node_setup_api import RKSNodeSetupApi
from rks.api.rks_secrets_api import RKSSecretsApi
from rks.configuration import Configuration
from rks.rest import ApiException


from rks.models.secret import Secret
from rks.models.secret_data import SecretData
from rks.models.secret_data_meta import SecretDataMeta
from . import utils

CA_BUNDLE_PATH = "./certs/rks_CA.pem"

# Add command line parameter
def pytest_addoption(parser):
    parser.addoption("--rks-url", default="https://rks.local:8080")
    parser.addoption("--vault-address", default="http://rks-vault:8200")
    parser.addoption("--admin-login", default="")
    parser.addoption("--admin-pwd", default="")
    parser.addoption(
        "--https", action="store_true", default=False, help="Launch tests with https"
    )

    # Setup root token from env if key exist
    root_token = os.environ.get("ROOT_TOKEN")
    if root_token != None:
        utils.ADMIN_TOKEN = root_token


def make_secret():
    secret = Secret(SecretData(meta=SecretDataMeta()))
    secret.data.certificate = "test"
    secret.data.private_key = "test"
    secret.data.meta.ttl = 10
    return secret


@pytest.fixture(scope="session", autouse=True)
def init_rks(request, api_configuration):
    print("calling INIT_RKS FIXTURE")
    conf = copy.deepcopy(api_configuration)
    conf.api_key["X-Vault-Token"] = utils.ADMIN_TOKEN
    init_api = RKSInitializationApi(rks.api_client.ApiClient(conf))
    try:
        resp, status, headers = init_api.init_rks_with_http_info()
    except ApiException as e:
        if e.status == 409:
            warnings.warn(UserWarning("RKS Already initialized"))
        else:
            raise e


@pytest.fixture
def test_dot_com_secret(admin_api):
    s = make_secret()
    admin_api.create_secret("test.com", s)
    yield s
    admin_api.delete_secret("test.com")


# Register parameter inside test classes using pytest fixture
@pytest.fixture(scope="session")
def rks_url(request):
    # request.cls.rks_url = request.config.getoption("--rks-url")
    return request.config.getoption("--rks-url")


@pytest.fixture(scope="session")
def vault_address(request):
    return request.config.getoption("--vault-address")


@pytest.fixture(scope="session")
def https_enabled(request):
    return request.config.getoption("--https")


@pytest.fixture(scope="session")
def admin_login(request):
    # request.cls.rks_url = request.config.getoption("--admin-login")
    return request.config.getoption("--admin-login")


@pytest.fixture(scope="session")
def admin_pwd(request):
    # request.cls.rks_url = request.config.getoption("--admin-pwd")
    return request.config.getoption("--admin-pwd")


# Set requests library to trust given CA file if https is enabled
@pytest.fixture(autouse=True)
def set_requests_ca_bundle(https_enabled, monkeypatch):
    if https_enabled:
        monkeypatch.setitem(os.environ, "REQUEST_CA_BUNDLE", CA_BUNDLE_PATH)


# Build api configuration object using command line options
@pytest.fixture(scope="session")
def api_configuration(rks_url, https_enabled):
    conf = rks.configuration.Configuration()
    conf.host = rks_url
    if https_enabled:
        conf.ssl_ca_cert = CA_BUNDLE_PATH
    return conf


@pytest.fixture
def admin_api(request, api_configuration, admin_login, admin_pwd):
    conf = copy.deepcopy(api_configuration)
    admin_unlogged_api = RKSAdministrationApi(rks.api_client.ApiClient(conf))
    admin_credentials = rks.models.admin_credentials.AdminCredentials(
        admin_login, admin_pwd
    )
    admin_token = admin_unlogged_api.login_admin(admin_credentials)
    conf.api_key["X-Vault-Token"] = admin_token.admin_token
    return RKSAdministrationApi(rks.api_client.ApiClient(conf))


@pytest.fixture
def init_api(request, api_configuration):
    conf = copy.deepcopy(api_configuration)
    conf.api_key["X-Vault-Token"] = utils.ADMIN_TOKEN
    return RKSInitializationApi(rks.api_client.ApiClient(conf))


@pytest.fixture
def node_setup_api(api_configuration):
    # See group_setup_api comments
    conf = copy.deepcopy(api_configuration)
    return RKSNodeSetupApi(rks.api_client.ApiClient(conf))


@pytest.fixture
def secret_api(api_configuration):
    # See group_setup_api comments
    conf = copy.deepcopy(api_configuration)
    return RKSSecretsApi(rks.api_client.ApiClient(conf))


@pytest.fixture
def group_token(rks_url, admin_api):
    # Create a group named "fakecdn1" on RKS, return its group_token

    # Provision mockgroup with one allowed node (the one who will register)
    r = requests.put(
        "https://mock-callback-server:8081/callback/nodes/1",
        headers={"Authorization": "Bearer tokentest"},
        verify=False,
    )

    group_token = admin_api.create_group("fakecdn1", utils.group_reg_info)

    yield group_token

    admin_api.delete_group("fakecdn1")


@pytest.fixture
def group_token_wrong_oauth_credentials(rks_url, admin_api):
    # Create a group named "fakecdn1" on RKS, return its group_token

    # Provision mockgroup with one allowed node (the one who will register)
    r = requests.put(
        "https://mock-callback-server:8081/callback/nodes/1",
        headers={"Authorization": "Bearer tokentest"},
        verify=False,
    )

    group_token = admin_api.create_group(
        "fakecdn1", utils.group_reg_info_wrong_auth_credentials
    )

    yield group_token

    admin_api.delete_group("fakecdn1")


@pytest.fixture
def group_token_nocallbackurl(rks_url, admin_api):

    # Create a group named "fakecdn1" on RKS, return its group_token
    # In this fixtures, callbackUrl is not set so that there is no callback validation when node registers

    group_reg_info = rks.models.GroupRegInfo("", "", "", "")

    # Skip this part since mockgroup is not called in this case
    # Provision mockgroup with one allowed node (the one who will register)
    # r = requests.put(
    #    "https://mock-callback-server:8081/callback/nodes/1",
    #    headers={"Authorization": "Bearer tokentest"},
    #    verify=False,
    # )

    group_token = admin_api.create_group("fakecdn1", group_reg_info)

    yield group_token
    admin_api.delete_group("fakecdn1")


@pytest.fixture
def node_token(group_token, rks_url, node_setup_api):
    # Register a node on RKS and return its node_token
    # Registered node Id is 1 and its belong to group "fakecdn1"

    node_id = "1"

    node_setup_api.api_client.configuration.api_key[
        "X-Vault-Token"
    ] = group_token.group_token
    nodetoken = node_setup_api.register_node(node_id)

    return nodetoken.node_token


@pytest.fixture
def associate_dot_com_group(admin_api, test_dot_com_secret, group_token):
    # Associate "test.com" secret to group "fakecdn1"
    # return nothing
    admin_api.associate_secret("fakecdn1", "test.com")

    yield

    admin_api.dissociate_secret("fakecdn1", "test.com")

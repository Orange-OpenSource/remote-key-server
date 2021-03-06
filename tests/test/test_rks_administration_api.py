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
import pytest
import rks
import time
import requests
import copy

from rks.models.secret import Secret
from rks.models.secret_data import SecretData
from rks.models.secret_data_meta import SecretDataMeta
from rks.api.rks_administration_api import RKSAdministrationApi

from rks.rest import ApiException, ApiValueError
from . import utils


def make_secret():
    secret = Secret(SecretData(meta=SecretDataMeta()))
    secret.data.certificate = "test"
    secret.data.private_key = "test"
    secret.data.meta.ttl = 10
    return secret


class TestRKSAdministrationApi(object):
    def test_login_admin(self, request, api_configuration, admin_login, admin_pwd):
        """ Test case for login admin"""
        conf = copy.deepcopy(api_configuration)
        admin_unlogged_api = RKSAdministrationApi(rks.api_client.ApiClient(conf))
        admin_credentials = rks.models.admin_credentials.AdminCredentials(
            admin_login, admin_pwd
        )
        admin_token = admin_unlogged_api.login_admin(admin_credentials)
        assert type(admin_token) == rks.models.AdminToken
        assert admin_token.admin_token != ""

    def test_wrong_login_admin(self, request, api_configuration, admin_login):
        """ Test case for login admin"""
        conf = copy.deepcopy(api_configuration)
        admin_unlogged_api = RKSAdministrationApi(rks.api_client.ApiClient(conf))
        admin_credentials = rks.models.admin_credentials.AdminCredentials(
            admin_login, "wrongpassword"
        )

        with pytest.raises(ApiException) as excinfo:
            (
                admin_token,
                status,
                headers,
            ) = admin_unlogged_api.login_admin_with_http_info(admin_credentials)
        assert (
            excinfo.value.status == 400
        ), "wrong status code when login failed because of wrong password"

        """note here : to fix:
        When attemping to login with wrong login: excinfo.status = 404
        but server with curl request answers 400: can't see the request in rks logs
        ....mysterious
        """

    #        admin_credentials = rks.models.admin_credentials.AdminCredentials("wronglogin","wrongpassword")
    #        with pytest.raises(ApiException) as excinfo:
    #            admin_token, status, headers = admin_unlogged_api.login_admin_with_http_info(
    #                admin_credentials
    #            )
    #        assert (
    #            excinfo.value.status == 400
    #        ), "wrong status code when login failed because of wrong password"
    #
    def test_create_group(self, admin_api):
        """Test case for create_group

        Register a Group of Nodes, then register again and test 408 response  # noqa: E501
        """

        group_token = rks.models.group_token.GroupToken()
        group_token, status, headers = admin_api.create_group_with_http_info(
            "fakecdn1", utils.group_reg_info
        )
        assert (
            group_token is not None
            and type(group_token) == rks.models.group_token.GroupToken
            and status == 201
        )

        with pytest.raises(ApiException) as excinfo:
            group_token, status, headers = admin_api.create_group_with_http_info(
                "fakecdn1", utils.group_reg_info
            )
        assert (
            excinfo.value.status == 409
        ), "Registering an already registered group does not fail (must return 409)"

        # Test groupname with invalid characters
        with pytest.raises(ApiValueError) as excinfo:
            group_token, status, headers = admin_api.create_group_with_http_info(
                "f%µecdn1", utils.group_reg_info
            )
        # Test rksclient return and Exception when groupname does not match specifications requirements

        # Test groupname with more than 64 characters
        with pytest.raises(ApiValueError) as excinfo:
            group_token, status, headers = admin_api.create_group_with_http_info(
                "d7b33fbc-007d-11ea-95ba-2f865341a298-d7b33fbc-007d-11ea-95ba-2f865341a298",
                utils.group_reg_info,
            )
        # Test rksclient return and Exception when groupname does not match specifications requirements

        # Test with incorrect admin_api key => must return 403
        admin_api.api_client.configuration.api_key["X-Vault-Token"] = utils.WRONG_TOKEN
        with pytest.raises(ApiException) as excinfo:
            group_token, status, headers = admin_api.create_group_with_http_info(
                "fakecdn1", utils.group_reg_info
            )
        assert (
            excinfo.value.status == 403
        ), "Invalid Token does not return Forbidden (must return 403)"

        # reset admin_api with root token and delete group
        admin_api.api_client.configuration.api_key["X-Vault-Token"] = utils.ADMIN_TOKEN

        response, status, headers = admin_api.delete_group_with_http_info("fakecdn1")
        assert status == 204, "Delete group does not return 204 as expected"

    def test_update_group_token(
        self,
        admin_api,
        group_token,
        node_setup_api,
        node_token,
        secret_api,
        test_dot_com_secret,
        associate_dot_com_group,
    ):
        # test update grouptoken
        new_group_token, status, headers = admin_api.update_group_token_with_http_info(
            "fakecdn1"
        )
        assert (
            new_group_token is not None
            and type(new_group_token) == rks.models.group_token.GroupToken
            and status == 200
        )

        group_token_test = admin_api.get_group_token("fakecdn1")

        assert (
            group_token_test.group_token == new_group_token.group_token
        ), "group_token not well updated in rks"

        # Test group_token has correctly been revoked
        # in trying to register again node with old group token

        node_setup_api.api_client.configuration.api_key[
            "X-Vault-Token"
        ] = group_token.group_token

        with pytest.raises(ApiException) as excinfo:
            (
                nodeToken,
                responseStatus,
                headers,
            ) = node_setup_api.register_node_with_http_info(
                "1", _return_http_data_only=False
            )
        assert excinfo.value.status == 403

        # Test node_token have been revoked too (as childs of group_token)
        # so that node can't get secret anymore
        secret_api.api_client.configuration.api_key["X-Vault-Token"] = node_token
        with pytest.raises(ApiException) as excinfo:
            secret, responseStatus, headers = secret_api.get_secret("test.com")
        assert excinfo.value.status == 403

        # Test new group token give the ability to register node again
        node_setup_api.api_client.configuration.api_key[
            "X-Vault-Token"
        ] = new_group_token.group_token

        (
            nodeToken,
            responseStatus,
            headers,
        ) = node_setup_api.register_node_with_http_info(
            "1", _return_http_data_only=False
        )
        print(nodeToken)
        assert type(nodeToken) == rks.models.NodeToken and nodeToken != "None"
        assert responseStatus == 201

    def test_update_group(self, admin_api, group_token):
        """Test case for update_group

        Update a Group of Nodes to update registration information
        """

        _, status, headers = admin_api.update_group_with_http_info(
            "fakecdn1", utils.group_reg_info_updated
        )
        assert status == 200

        group_reg_info, status, headers = admin_api.get_group_with_http_info("fakecdn1")
        assert (
            group_reg_info == utils.group_reg_info_updated
        ), "Group registration information not well updated"

        with pytest.raises(ApiException) as excinfo:
            _, status, headers = admin_api.update_group_with_http_info(
                "fakecdn11", utils.group_reg_info_updated
            )
        assert (
            excinfo.value.status == 404
        ), "Updating an unknown group does not fail (must return 404)"

        # Test groupname with invalid characters
        with pytest.raises(ApiValueError) as excinfo:
            _, status, headers = admin_api.update_group_with_http_info(
                "f%µecdn1", utils.group_reg_info_updated
            )
        # Test rksclient return and Exception when groupname does not match specifications requirements

        # Test groupname with more than 64 characters
        with pytest.raises(ApiValueError) as excinfo:
            _, status, headers = admin_api.update_group_with_http_info(
                "d7b33fbc-007d-11ea-95ba-2f865341a298-d7b33fbc-007d-11ea-95ba-2f865341a298",
                utils.group_reg_info_updated,
            )
        # Test rksclient return and Exception when groupname does not match specifications requirements

        # Test with incorrect admin_api key => must return 403
        admin_api.api_client.configuration.api_key["X-Vault-Token"] = utils.WRONG_TOKEN
        with pytest.raises(ApiException) as excinfo:
            _, status, headers = admin_api.update_group_with_http_info(
                "fakecdn1", utils.group_reg_info
            )
        assert (
            excinfo.value.status == 403
        ), "Invalid Token does not return Forbidden (must return 403)"

        # reset admin_api with root token and delete group
        admin_api.api_client.configuration.api_key["X-Vault-Token"] = utils.ADMIN_TOKEN

    def test_get_group(self, admin_api, group_token):
        """Test case for get_group
        """

        group_reg_info, status, headers = admin_api.get_group_with_http_info("fakecdn1")
        assert status == 200, "Status code should be 200 when OK"

        assert (
            group_reg_info == utils.group_reg_info
        ), "Group registration information not well read"

        with pytest.raises(ApiException) as excinfo:
            group_reg_info, status, headers = admin_api.get_group_with_http_info(
                "fakecdn11"
            )
        assert (
            excinfo.value.status == 404
        ), "Reading an unknown group does not fail (must return 404)"

        # Test groupname with invalid characters
        with pytest.raises(ApiValueError) as excinfo:
            group_reg_info, status, headers = admin_api.get_group_with_http_info(
                "f%µecdn1"
            )
        # Test rksclient return and Exception when groupname does not match specifications requirements

        # Test groupname with more than 64 characters
        with pytest.raises(ApiValueError) as excinfo:
            group_reg_info, status, headers = admin_api.get_group_with_http_info(
                "d7b33fbc-007d-11ea-95ba-2f865341a298-d7b33fbc-007d-11ea-95ba-2f865341a298"
            )
        # Test rksclient return and Exception when groupname does not match specifications requirements

        # Test with incorrect admin_api key => must return 403
        admin_api.api_client.configuration.api_key["X-Vault-Token"] = utils.WRONG_TOKEN
        with pytest.raises(ApiException) as excinfo:
            group_reg_info, status, headers = admin_api.get_group_with_http_info(
                "fakecdn1"
            )
        assert (
            excinfo.value.status == 403
        ), "Invalid Token does not return Forbidden (must return 403)"

        # reset admin_api with root token and delete group
        admin_api.api_client.configuration.api_key["X-Vault-Token"] = utils.ADMIN_TOKEN

    def test_delete_group(
        self, admin_api, node_setup_api, secret_api, test_dot_com_secret,
    ):

        group_token = rks.models.group_token.GroupToken()
        group_token, status, headers = admin_api.create_group_with_http_info(
            "fakecdn3", utils.group_reg_info
        )
        # normal test case (status==204) already tested on test_create_group and called in group_token fixture
        # Test with incorrect admin_api key => must return 403
        admin_api.api_client.configuration.api_key["X-Vault-Token"] = utils.WRONG_TOKEN

        with pytest.raises(ApiException) as excinfo:
            response, status, headers = admin_api.delete_group_with_http_info(
                "fakecdn3"
            )
        assert (
            excinfo.value.status == 403
        ), "Invalid Token does not return Forbidden (must return 403)"

        admin_api.api_client.configuration.api_key["X-Vault-Token"] = utils.ADMIN_TOKEN

        # Test delete wrong group name
        with pytest.raises(ApiException) as excinfo:
            response, status, headers = admin_api.delete_group_with_http_info(
                "wrongfakecdn"
            )
        assert (
            excinfo.value.status == 404
        ), "Invalid groupName does not return not found (must return 404)"

        # register node with this group_token
        node_setup_api.api_client.configuration.api_key[
            "X-Vault-Token"
        ] = group_token.group_token

        node_token = node_setup_api.register_node("1")
        # associate test_dot_com secret to fakecdn3
        admin_api.associate_secret("fakecdn3", "test.com")

        # try to get secret
        secret_api.api_client.configuration.api_key[
            "X-Vault-Token"
        ] = node_token.node_token
        secret = secret_api.get_secret("test.com")

        assert secret.data != None
        assert secret.data.certificate != None
        assert secret.data.private_key != None
        assert secret.data.meta != None

        # finally delete normally it
        response, status, headers = admin_api.delete_group_with_http_info("fakecdn3")
        assert status == 204, "Incorrect status code on delete (must return 204)"

        # Test group_token has correctly been revoked
        # in trying to register node with it

        with pytest.raises(ApiException) as excinfo:
            (
                nodeToken,
                responseStatus,
                headers,
            ) = node_setup_api.register_node_with_http_info(
                "1", _return_http_data_only=False
            )
        assert excinfo.value.status == 403

        # Test node_token have been revoked too (as childs of group_token)
        # so that node can't get secret anymore
        with pytest.raises(ApiException) as excinfo:
            secret, responseStatus, headers = secret_api.get_secret("test.com")
        assert excinfo.value.status == 403

        # Test all group datas have been deleted
        with pytest.raises(ApiException) as excinfo:
            group_reg_info = admin_api.get_group_config("fakecdn3")
        assert excinfo.value.status == 404

        with pytest.raises(ApiException) as excinfo:
            grouptoken = admin_api.get_group_token("fakecdn3")
        assert excinfo.value.status == 404

    def test_multiple_init(self, init_api, rks_url):

        # Test with incorrect admin_api key => must return 403
        init_api.api_client.configuration.api_key["X-Vault-Token"] = utils.WRONG_TOKEN

        with pytest.raises(rks.rest.ApiException) as excinfo:
            response, status, headers = init_api.init_rks_with_http_info()
        assert (
            excinfo.value.status == 403
        ), "Error calling init with wrong token must return 403 code"

        init_api.api_client.configuration.api_key["X-Vault-Token"] = utils.ADMIN_TOKEN

        with pytest.raises(rks.rest.ApiException) as excinfo:
            response, status, headers = init_api.init_rks_with_http_info()
        assert (
            excinfo.value.status == 409
        ), "Error with multiple init, must return 409 code"

    def test_init_without_content_type_header(self, rks_url):

        # test a call to init endpoint without content-type header fix #1
        response = requests.post(
            rks_url + "/rks/v1/init",
            headers={"X-Vault-Token": utils.ADMIN_TOKEN},
            verify=False,
        )
        assert response.status_code == 409

    def test_get_secret(self, admin_api, test_dot_com_secret):
        s = admin_api.get_secret("test.com")
        assert s != None
        assert s.data.certificate != None
        assert s.data.private_key != None
        assert s.data.meta != None

    def test_create_secret(self, admin_api):
        secret = make_secret()
        admin_api.create_secret("test_create.com", secret)

        s = admin_api.get_secret("test_create.com")
        assert s != None
        admin_api.delete_secret("test_create.com")

    def test_create_existing_secret(self, admin_api, test_dot_com_secret):
        with pytest.raises(ApiException) as excinfo:
            admin_api.create_secret("test.com", test_dot_com_secret)
        assert excinfo.value.status == 409

    def test_update_secret(self, admin_api, test_dot_com_secret):
        test_dot_com_secret.data.certificate = "updated"
        admin_api.update_secret("test.com", test_dot_com_secret)

        s = admin_api.get_secret("test.com")
        assert s.data.certificate == "updated"

    def test_update_nonexistent_secret(self, admin_api):
        with pytest.raises(ApiException) as excinfo:
            secret = make_secret()
            admin_api.update_secret("nonexistent.com", secret)
        assert excinfo.value.status == 404

    def test_delete_secret(self, admin_api, group_token):
        secret = make_secret()
        admin_api.create_secret("test_delete.com", secret)
        s = admin_api.get_secret("test_delete.com")
        assert s != None

        admin_api.delete_secret("test_delete.com")
        with pytest.raises(ApiException) as excinfo:
            s = admin_api.get_secret("test_delete.com")
        assert excinfo.value.status == 404

        admin_api.create_secret("test_delete.com", secret)
        admin_api.associate_secret("fakecdn1", "test_delete.com")
        with pytest.raises(ApiException) as excinfo:
            admin_api.delete_secret("test_delete.com")
        assert excinfo.value.status == 409

        admin_api.dissociate_secret("fakecdn1", "test_delete.com")
        admin_api.delete_secret("test_delete.com")

        with pytest.raises(ApiException) as excinfo:
            s = admin_api.get_secret("test_delete.com")
        assert excinfo.value.status == 404

    def test_delete_nonexistent_secret(self, admin_api):
        with pytest.raises(ApiException) as excinfo:
            admin_api.delete_secret("nonexistent.com")
        assert excinfo.value.status == 404

    def test_get_group_secrets(self, admin_api, group_token, test_dot_com_secret):
        admin_api.associate_secret("fakecdn1", "test.com")
        group_secrets = admin_api.get_group_secrets("fakecdn1")

        assert "test.com" in group_secrets
        admin_api.dissociate_secret("fakecdn1", "test.com")

        group_secrets = admin_api.get_group_secrets("fakecdn1")
        assert "test.com" not in group_secrets

    def test_associate_secret(
        self, admin_api, test_dot_com_secret, secret_api, group_token, node_token
    ):
        secret_api.api_client.configuration.api_key["X-Vault-Token"] = node_token
        with pytest.raises(ApiException) as excinfo:
            secret = secret_api.get_secret("test.com")

        admin_api.associate_secret("fakecdn1", "test.com")

        secret = secret_api.get_secret("test.com")
        assert secret != None
        admin_api.dissociate_secret("fakecdn1", "test.com")

    def test_dissociate_secret(
        self, admin_api, test_dot_com_secret, secret_api, node_token
    ):
        admin_api.associate_secret("fakecdn1", "test.com")

        secret_api.api_client.configuration.api_key["X-Vault-Token"] = node_token
        secret = secret_api.get_secret("test.com")
        assert secret != None

        admin_api.dissociate_secret("fakecdn1", "test.com")
        with pytest.raises(ApiException) as excinfo:
            secret = secret_api.get_secret("test.com")
        assert excinfo.value.status == 403

    def test_get_group_config(self, admin_api, group_token):
        group_reg_info = admin_api.get_group_config("fakecdn1")

        assert group_reg_info.__eq__(utils.group_reg_info)

        with pytest.raises(ApiException) as excinfo:
            group_reg_info = admin_api.get_group_config("wrongfakecdn1")
        assert excinfo.value.status == 404

    def test_get_group_token(self, admin_api, group_token):
        grouptoken = admin_api.get_group_token("fakecdn1")

        assert grouptoken.__eq__(group_token)

        with pytest.raises(ApiException) as excinfo:
            grouptoken = admin_api.get_group_token("wrongfakecdn1")
        assert excinfo.value.status == 404

    def test_get_secrets_groups(self, admin_api, group_token, test_dot_com_secret):

        admin_api.associate_secret("fakecdn1", "test.com")
        group_names = admin_api.get_secret_groups("test.com")
        assert "fakecdn1" in group_names

        admin_api.dissociate_secret("fakecdn1", "test.com")
        group_names = admin_api.get_secret_groups("test.com")
        assert not group_names

        with pytest.raises(ApiException) as excinfo:
            group_names = admin_api.get_secret_groups("testnotexist.com")
        assert excinfo.value.status == 404

    def test_revoke_node(
        self,
        admin_api,
        secret_api,
        node_token,
        associate_dot_com_group,
        test_dot_com_secret,
    ):

        secret_api.api_client.configuration.api_key["X-Vault-Token"] = node_token

        secret = secret_api.get_secret("test.com")

        assert secret.data != None, "revoke failed"
        assert secret.data.certificate != None, "revoke failed"
        assert secret.data.private_key != None, "revoke failed"
        assert secret.data.meta != None, "revoke failed"

        _, status, headers = admin_api.revoke_node_with_http_info("fakecdn1", "1")

        assert status == 204, "revoke node does not return 204 as expected"

        try:
            secret = secret_api.get_secret("test.com")
        except ApiException as e:
            assert (
                e.status == 403
            ), "getting secret with revoked nodeToken does not return 403 as expected"

        # test revoke unknown nodeId
        _, status, headers = admin_api.revoke_node_with_http_info("fakecdn1", "10")

        assert status == 204, "revoke unknown nodeId does not return 204 as expected"

        with pytest.raises(ApiException) as ex:
            # test revoke unknown groupname nodeId
            admin_api.revoke_node("unknowngroupname", "1")

        assert (
            ex.value.status == 404
        ), "revoke nodeId from unknown group does not return 404 as expected"

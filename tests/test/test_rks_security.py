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
# coding: utf-8

"""
    Remote Key Server API

    Describes RKS API  # noqa: E501

    OpenAPI spec version: 0.4.0
    Generated by: https://openapi-generator.tech
"""


from __future__ import absolute_import

import pytest
import requests
import json
import rks
from . import utils

from rks.rest import ApiException


class TestRKSSecurity(object):
    """RKSSecurity checkings unit test stubs"""

    def test_get_secret_with_gzip_content_encoding(
        self,
        rks_url,
        secret_api,
        node_token,
        test_dot_com_secret,
        associate_dot_com_group,
    ):
        headers = {"Content-Encoding": "gzip", "X-Vault-Token": node_token}

        response = requests.get(
            rks_url + "/rks/v1/secret/test.com", headers=headers, verify=False
        )

        assert response.status_code == 400

    def test_get_secret_with_body(
        self,
        rks_url,
        secret_api,
        node_token,
        test_dot_com_secret,
        associate_dot_com_group,
    ):
        headers = {"X-Vault-Token": node_token, "Content-Type": "application/json"}

        data = {"testdata": "nothingtodohere"}
        response = requests.get(
            rks_url + "/rks/v1/secret/test.com",
            headers=headers,
            verify=False,
            data=json.dumps(data),
        )
        assert response.status_code == 404

    def test_init_with_body(self, rks_url):
        headers = {
            "X-Vault-Token": utils.ADMIN_TOKEN,
            # "Content-Type": "application/json",
        }
        data = {"testdata": "nothingtodohere"}

        response = requests.post(
            rks_url + "/rks/v1/init",
            headers=headers,
            data=json.dumps(data),
            verify=False,
        )
        assert response.status_code == 404

    def test_create_secret_wrong_schema(self, rks_url, admin_api):
        secret = json.dumps(
            {
                "a": {
                    "a": {
                        "a": {
                            "a": {
                                "a": {
                                    "a": {
                                        "a": {
                                            "a": {
                                                "a": {
                                                    "a": {
                                                        "a": {
                                                            "a": {
                                                                "a": "toto",
                                                                "toto": "toto",
                                                            },
                                                            "toto": "toto",
                                                        },
                                                        "toto": "toto",
                                                    },
                                                    "toto": "toto",
                                                },
                                                "toto": "toto",
                                            },
                                            "toto": "toto",
                                        },
                                        "toto": "toto",
                                    },
                                    "toto": "toto",
                                },
                                "toto": "toto",
                            },
                            "toto": "toto",
                        },
                        "toto": "toto",
                    },
                    "toto": "toto",
                },
                "b": [
                    [
                        [
                            [
                                [
                                    [
                                        [
                                            [
                                                [
                                                    [
                                                        [["toto", "toto"], "toto"],
                                                        "toto",
                                                    ],
                                                    "toto",
                                                ],
                                                "toto",
                                            ],
                                            "toto",
                                        ],
                                        "toto",
                                    ],
                                    "toto",
                                ],
                                "toto",
                            ],
                            "toto",
                        ],
                        "toto",
                    ],
                    "toto",
                ],
                "1": 1,
                "2": 2,
                "3": 3,
                "4": 4,
                "5": 5,
                "6": 6,
                "7": 7,
                "8": 8,
                "9": 9,
                "10": 10,
                "11": 11,
                "12": 12,
            }
        )

        headers = {
            "X-Vault-Token": admin_api.api_client.configuration.api_key[
                "X-Vault-Token"
            ],
            "Content-Type": "application/json",
        }

        response = requests.post(
            rks_url + "/rks/v1/secret/test1.com",
            headers=headers,
            verify=False,
            data=secret,
        )

        assert response.status_code == 400

        secret = json.dumps(
            {
                "a": {
                    "a": {
                        "a": {
                            "a": {
                                "a": {
                                    "a": {
                                        "a": {
                                            "a": {
                                                "a": {
                                                    "a": {
                                                        "a": {
                                                            "a": {
                                                                "a": None,
                                                                "None": None,
                                                            },
                                                            "None": None,
                                                        },
                                                        "None": None,
                                                    },
                                                    "None": None,
                                                },
                                                "None": None,
                                            },
                                            "None": None,
                                        },
                                        "None": None,
                                    },
                                    "None": None,
                                },
                                "None": None,
                            },
                            "None": None,
                        },
                        "None": None,
                    },
                    "None": None,
                },
                "b": [
                    [
                        [
                            [
                                [
                                    [
                                        [
                                            [
                                                [[[[None, None], None], None], None],
                                                None,
                                            ],
                                            None,
                                        ],
                                        None,
                                    ],
                                    None,
                                ],
                                None,
                            ],
                            None,
                        ],
                        None,
                    ],
                    None,
                ],
                "1": 1,
                "2": 2,
                "3": 3,
                "4": 4,
                "5": 5,
                "6": 6,
                "7": 7,
                "8": 8,
                "9": 9,
                "10": 10,
                "11": 11,
                "12": 12,
            }
        )

        response = requests.post(
            rks_url + "/rks/v1/secret/test.com",
            headers=headers,
            verify=False,
            data=secret,
        )
        assert response.status_code == 400


if __name__ == "__main__":
    pytest.main()

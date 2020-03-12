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
import rks

# Token for admin API == Vault root token for the moment
ADMIN_TOKEN = "root"

# Wrong Token for all API
WRONG_TOKEN = "wrong_token"

# group_reg_info for all tests
group_reg_info = rks.models.GroupRegInfo(
    "https://mock-callback-server:8081/callback/nodes",
    "https://mock-callback-server:8081/api/identity/oauth/token",
    "f146c93f-00af-42a2-9667-8c0d99b37953",
    "da5edef7-1664-42b9-8fa7-5a107e7cca32",
)

# group_reg_info for update_group test
group_reg_info_updated = rks.models.GroupRegInfo(
    "https://mock-callback-server:8081/callback/nodes",
    "https://mock-callback-server:8081/api/identity/oauth/token",
    "f146c93f-00af-42a2-9667-8c0d99b37953i-updated",
    "da5edef7-1664-42b9-8fa7-5a107e7cca32-updated",
)

# group_reg_info for all tests
group_reg_info_wrong_auth_credentials = rks.models.GroupRegInfo(
    "https://mock-callback-server:8081/callback/nodes",
    "https://mock-callback-server:8081/api/identity/oauth/token",
    "wronguser",
    "da5edef7-1664-42b9-8fa7-5a107e7cca32",
)

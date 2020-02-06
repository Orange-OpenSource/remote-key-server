/*
Software Name : Remote Key Server
Version: 0.9.0
SPDX-FileCopyrightText: Copyright (c) 2020 Orange
SPDX-License-Identifier: MPL-2.0

This software is distributed under the Mozilla Public License 2.0,
the text of which is available at https://www.mozilla.org/en-US/MPL/2.0/
or see the "LICENSE" file for more details.

Author: Glenn Feunteun, Celine Nicolas
*/
package vault

const GroupSecretAccessPolicy = `# Group secret access policy
	path "auth/token/renew-self" {
		capabilities =  ["read", "create", "update"]
	}
{{ range . }}
	path "rks/data/{{.}}" {
		capabilities = ["read"]
}
{{ end }}`

const GroupInitAccessPolicy = `
	path "auth/token/renew-self" {
		capabilities =  ["read", "create", "update"]
	}
`

const GroupTokenAccessPolicy = `
	path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "rks/data/groups/{{.}}/*" {
  capabilities = ["create","update","read"]
}

path "auth/token/roles/{{.}}-*" {
  capabilities = ["create","update","read"]
}

path "auth/token/create/{{.}}-*" {
  capabilities = ["create","update","read"]
}

path "auth/token/renew-self"{
  capabilities=["create","update","read"]
}`

const AdminPolicy = `
path "rks/*" {
  capabilities = ["create","update","read","list","delete"]
}

path "sys/policies/*" {
  capabilities = ["create","update","read","delete"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/roles/*" {
  capabilities = ["create","update","read","delete"]
}

path "auth/token/create/*" {
  capabilities = ["create","update","read"]
}

path "auth/token/revoke" {
  capabilities = ["create","update","read"]
}
path "auth/token/renew-self"{
  capabilities=["create","update","read"]
}`

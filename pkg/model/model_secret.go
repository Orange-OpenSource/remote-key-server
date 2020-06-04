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
package model

type Secret struct {
	Data SecretData `json:"data,omitempty" mapstructure:"data"`
}

type SecretData struct {
	Meta        SecretDataMeta `json:"meta,omitempty" mapstructure:"meta"`
	Certificate string         `json:"certificate,omitempty" mapstructure:"certificate"`
	PrivateKey  string         `json:"private_key,omitempty" mapstructure:"private_key"`
}

type SecretDataMeta struct {
	Ttl int32 `json:"ttl,omitempty" mapstructure:"ttl"`
}

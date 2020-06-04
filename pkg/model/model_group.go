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

type GroupPassword struct {
	Password string `json:"password"`
}

type GroupRegInfo struct {
	CallbackURL       string `json:"callbackURL"`
	OauthURL          string `json:"oauthURL"`
	OauthClientID     string `json:"oauthClientID"`
	OauthClientSecret string `json:"oauthClientSecret"`
}

type GroupToken struct {
	GroupToken string `json:"groupToken,omitempty"`
}

type GroupSecrets struct {
	Secrets []string `json:"secrets"`
}

//For internal use
type TokenAuth struct {
	ClientToken string `json:"client_token,omitempty"`
}

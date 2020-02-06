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
package initialize

import (
	"net/http"

	"github.com/Orange-OpenSource/remote-key-server/logger"
	"github.com/Orange-OpenSource/remote-key-server/model"
	"github.com/Orange-OpenSource/remote-key-server/vault"
)

func InitRKS(w http.ResponseWriter, r *http.Request) {
	customLogger := logger.NewLoggerFromContext(r.Context())

	customLogger.WithField("token", r.Header.Get("X-Vault-Token")).Debug("token used")

	vaultClient, err := vault.NewVaultClientFromHTTPRequest(r)
	if err != nil {
		err.HandleErr(r.Context(), w)
		return
	}
	if exists, err := vaultClient.ConfigExists(); err != nil {
		err.HandleErr(r.Context(), w)
		return
	} else if exists {
		(&model.RksError{WrappedError: nil, Message: "RKS already initialized", Code: 409}).HandleErr(r.Context(), w)
		return
	}

	customLogger.Info("setup RKS key/value secret backend")
	if err := vaultClient.InitKvBackend(); err != nil {
		err.HandleErr(r.Context(), w)
		return
	}
	if err := vaultClient.EnableAdminUserpassBackend(); err != nil {
		err.HandleErr(r.Context(), w)
		return
	}

	vault.Config.VaultInitialized = true
	if err := vaultClient.WriteConfig(); err != nil {
		err.HandleErr(r.Context(), w)
		return
	}
	w.WriteHeader(http.StatusCreated)
	logger.WithResponseStatus(customLogger, w).Info("initialized rks")
}

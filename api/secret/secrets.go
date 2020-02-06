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
package secret

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/Orange-OpenSource/remote-key-server/logger"
	"github.com/Orange-OpenSource/remote-key-server/model"
	"github.com/Orange-OpenSource/remote-key-server/utils"
	"github.com/Orange-OpenSource/remote-key-server/vault"
)

func GetSecret(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fqdn := vars["fqdn"]

	customLogger := logger.NewLoggerFromContext(r.Context()).WithField("fqdn", fqdn)
	vaultClient, rksErr := vault.NewVaultClientFromHTTPRequest(r)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}
	//comment for further used with bound_cidr
	//vHeaders := vaultClient.Headers()
	//vHeaders.Add("X-Forwarded-For", strings.Split(getIPAddress(r), ":")[0])
	//vaultClient.SetHeaders(vHeaders)

	if exists, rksErr := vaultClient.SecretExists(fqdn); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	} else if !exists {
		(&model.RksError{WrappedError: nil, Message: "secret not found", Code: 404}).HandleErr(r.Context(), w)
		return
	}

	secret := model.Secret{}
	//Read Secret in vault
	if rksErr = vaultClient.ReadSecretIntoStruct("rks/data/"+fqdn, &secret.Data); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	if err := utils.WriteStructAsJSON(w, secret); err != nil {
		err.HandleErr(r.Context(), w)
		return
	}
	customLogger.Info("get secret")
}

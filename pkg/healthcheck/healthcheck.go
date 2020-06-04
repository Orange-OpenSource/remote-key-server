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
package healthcheck

import (
	"context"
	"net/http"

	"github.com/Orange-OpenSource/remote-key-server/pkg/model"
	"github.com/Orange-OpenSource/remote-key-server/pkg/utils"
	"github.com/Orange-OpenSource/remote-key-server/pkg/vault"
	vaultAPI "github.com/hashicorp/vault/api"
)

type RKSHealth struct {
	RKSVersion     string                   `json:"rks_version"`
	VaultAddress   string                   `json:"vault_address"`
	VaultReachable bool                     `json:"vault_reachable"`
	VaultHealth    *vaultAPI.HealthResponse `json:"vault_health,omitempty"`
}

/*
	Check Vault connectivity and return health informations
	Return 200 if vault is reachable
	Return 500 if vault is unreachable
*/
func Healthcheck(config *vault.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vaultClient, rksErr := vault.NewVaultClient(context.Background(), "")
		if rksErr != nil {
			return
		}

		rksHealth := RKSHealth{RKSVersion: model.RKSVersion, VaultAddress: config.VaultAddr, VaultReachable: false}

		health, err := vaultClient.Sys().Health()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			rksErr = utils.WriteStructAsJSON(w, rksHealth)
			if rksErr != nil {
				rksErr.HandleErr(context.Background(), w)
			}
			return
		}
		rksHealth.VaultReachable = true
		rksHealth.VaultHealth = health

		if !health.Initialized || health.Sealed {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		rksErr = utils.WriteStructAsJSON(w, rksHealth)
		if rksErr != nil {
			rksErr.HandleErr(context.Background(), w)
			return
		}
	}
}

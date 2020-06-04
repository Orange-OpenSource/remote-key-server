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
package admin

import (
	"context"
	"time"

	"github.com/Orange-OpenSource/remote-key-server/pkg/model"
	"github.com/Orange-OpenSource/remote-key-server/pkg/vault"
	log "github.com/sirupsen/logrus"
)

// PeriodicGroupTokensRenew is to be launched as a goroutine
// It renews all group token periodically
func PeriodicGroupTokensRenew() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	log.Println("Start periodic groupToken renew goroutine")
	for range ticker.C {
		adminLoginVaultClient, rksErr := vault.NewVaultClient(context.Background(), "")
		if rksErr != nil {
			log.Println(rksErr)
			continue
		}

		adminToken, rksErr := adminLoginVaultClient.Login(vault.Config.AdminLogin, vault.Config.AdminPwd)
		if rksErr != nil {
			log.Println(rksErr)
			continue
		}

		adminVaultClient, rksErr := vault.NewVaultClient(context.Background(), adminToken.AdminToken)
		if rksErr != nil {
			log.Println(rksErr)
			continue
		}

		grouplist, rksErr := adminVaultClient.GetGroupList()
		if rksErr != nil {
			log.Println(rksErr)
			continue
		}

		// Iterate over all groups and renew their group token
		for _, groupname := range grouplist {
			customLogger := log.WithField("groupname", groupname)

			var groupToken *model.GroupToken

			if groupToken, rksErr = adminVaultClient.ReadGroupToken(groupname); rksErr != nil {
				customLogger.Error(rksErr)
				continue
			}

			groupVaultClient, rksErr := vault.NewVaultClient(context.Background(), groupToken.GroupToken)
			if rksErr != nil {
				customLogger.Error(rksErr)
				continue
			}

			vaultSecret, vaultErr := groupVaultClient.Auth().Token().RenewSelf(0)
			if vaultErr != nil || vaultSecret == nil || len(vaultSecret.Warnings) > 0 {
				customLogger.WithFields(log.Fields{"vault_err": vaultErr, "vault_secret": vaultSecret}).Error("couldn't renew group token")
				continue
			}
			customLogger.Info("renewed group token")
		}
	}
}

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
package node

import (
	"net/http"
	"regexp"

	"github.com/Orange-OpenSource/remote-key-server/pkg/logger"
	"github.com/Orange-OpenSource/remote-key-server/pkg/model"
	"github.com/Orange-OpenSource/remote-key-server/pkg/utils"
	"github.com/Orange-OpenSource/remote-key-server/pkg/vault"
	log "github.com/sirupsen/logrus"
)

var validNodeID = regexp.MustCompile(`^[a-zA-Z0-9\-]{1,64}$`)

func RegisterNode(w http.ResponseWriter, r *http.Request) {
	vaultClient, rksErr := vault.NewVaultClientFromHTTPRequest(r)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	nodeID := r.Header.Get("X-LCDN-nodeId")

	if nodeID == "" || !validNodeID.MatchString(nodeID) {
		(&model.RksError{WrappedError: nil, Message: "Invalid or non existend X-LCDN-nodeId", Code: 404}).HandleErr(r.Context(), w)
		return
	}

	group, rksErr := vaultClient.GetGroupNameFromGroupToken()
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	customLogger := logger.NewLoggerFromContext(r.Context()).WithFields(log.Fields{"node_id": nodeID, "groupname": group})

	groupRegInfo, rksErr := vaultClient.ReadGroupConfig(group)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	// Check that node is authorized to get a node token by calling the callback URL
	if groupRegInfo.CallbackURL != "" {
		if rksErr = Callback(r.Context(), groupRegInfo, nodeID); rksErr != nil {
			rksErr.HandleErr(r.Context(), w)
			return
		}
	} else {
		customLogger.Info("CallbackURL is unset, continue without checking node")
	}

	if rksErr = vaultClient.CreateNodeTokenRole(group, nodeID); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}
	customLogger.Debug("Successfully created role into vault")

	auth, rksErr := vaultClient.CreateNodeTokenFromRole(group, nodeID)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	customLogger.WithField("node_token", auth.Auth.ClientToken).Debug("Successfully created node token")

	nodeRKSToken := model.NodeToken{}
	nodeRKSToken.NodeToken = auth.Auth.ClientToken
	nodeRKSToken.Ttl = auth.Auth.LeaseDuration

	w.WriteHeader(http.StatusCreated)
	if rksErr := utils.WriteStructAsJSON(w, nodeRKSToken); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}
	logger.WithResponseStatus(customLogger, w).Info("registered node")
}

func RenewToken(w http.ResponseWriter, r *http.Request) {
	vaultClient, rksErr := vault.NewVaultClientFromHTTPRequest(r)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	customLogger := logger.NewLoggerFromContext(r.Context())

	vaultSecret, err := vaultClient.Auth().Token().RenewSelf(0)
	if err != nil || vaultSecret == nil || len(vaultSecret.Warnings) > 0 {
		if vaultSecret != nil {
			log.Println(vaultSecret.Warnings)
		}
		(&model.RksError{WrappedError: err, Message: "{\"errors\":[\"permission denied\"]}", Code: http.StatusForbidden}).HandleErr(r.Context(), w)
		return
	}

	if log.GetLevel() == log.DebugLevel {
		customLogger.WithField("token", vaultSecret.Auth.ClientToken).Debug("Renewed token")
	}

	nodeToken := model.NodeToken{}
	nodeToken.NodeToken = vaultSecret.Auth.ClientToken
	nodeToken.Ttl = vaultSecret.Auth.LeaseDuration

	w.WriteHeader(http.StatusOK)
	if rksErr = utils.WriteStructAsJSON(w, nodeToken); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}
	logger.WithResponseStatus(customLogger, w).Info("renewed token")
}

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
	"net/http"
	"sort"

	"github.com/Orange-OpenSource/remote-key-server/logger"
	"github.com/Orange-OpenSource/remote-key-server/model"
	"github.com/Orange-OpenSource/remote-key-server/utils"
	"github.com/Orange-OpenSource/remote-key-server/vault"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

func Login(w http.ResponseWriter, r *http.Request) {
	adminCredentials := model.AdminCredentials{}
	if rksErr := utils.DecodeHTTPJSONBodyToStruct(r, &adminCredentials); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}
	customLogger := logger.NewLoggerFromContext(r.Context()).WithField("adminlogin", adminCredentials.Login)

	// new vault client without token to login admin
	vaultClient, rksErr := vault.NewVaultClient(r.Context(), "")
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	customLogger.WithField("pwd", adminCredentials.Password).Debug("")
	adminToken, rksErr := vaultClient.Login(adminCredentials.Login, adminCredentials.Password)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	if err := utils.WriteStructAsJSON(w, adminToken); err != nil {
		err.HandleErr(r.Context(), w)
		return
	}
	logger.WithResponseStatus(customLogger, w).Info("admin logged in")
}

func CreateGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	group := vars["groupname"]

	customLogger := logger.NewLoggerFromContext(r.Context()).WithField("groupname", group)
	r = r.WithContext(logger.ContextWithLogger(r.Context(), customLogger))

	customLogger.WithField("token", r.Header.Get("X-Vault-Token")).Debug("token used")
	vaultClient, rksErr := vault.NewVaultClientFromHTTPRequest(r)

	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	groupRegInfo := model.GroupRegInfo{}
	if rksErr := utils.DecodeHTTPJSONBodyToStruct(r, &groupRegInfo); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	if exists, rksErr := vaultClient.GroupExists(group); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	} else if exists {
		(&model.RksError{WrappedError: nil, Message: "Conflict, Group with this name already exists, unable to create group", Code: 409}).HandleErr(r.Context(), w)
		return
	}

	//Write Group config in vault
	if rksErr := vaultClient.WriteGroupConfig(group, &groupRegInfo); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}
	//write group and node policies, and create grouptoken in vault
	groupToken, rksErr := vaultClient.CreateGroupTokenAndPolicies(group)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	//Write Group token in vault
	if rksErr := vaultClient.WriteGroupToken(group, groupToken); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	w.WriteHeader(http.StatusCreated)
	if err := utils.WriteStructAsJSON(w, groupToken); err != nil {
		err.HandleErr(r.Context(), w)
		return
	}
	logger.WithResponseStatus(customLogger, w).Info("created group")
}

func UpdateGroup(w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)
	group := vars["groupname"]

	customLogger := logger.NewLoggerFromContext(r.Context()).WithField("groupname", group)
	r = r.WithContext(logger.ContextWithLogger(r.Context(), customLogger))

	customLogger.WithField("token", r.Header.Get("X-Vault-Token")).Debug("token used")
	vaultClient, rksErr := vault.NewVaultClientFromHTTPRequest(r)

	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	groupRegInfo := model.GroupRegInfo{}
	if rksErr := utils.DecodeHTTPJSONBodyToStruct(r, &groupRegInfo); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	if exists, rksErr := vaultClient.GroupExists(group); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	} else if !exists {
		(&model.RksError{WrappedError: nil, Message: "Group not found", Code: 404}).HandleErr(r.Context(), w)
		return
	}

	//Write Group config in vault
	if rksErr := vaultClient.WriteGroupConfig(group, &groupRegInfo); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	logger.WithResponseStatus(customLogger, w).Info("created group")

}
func DeleteGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	group := vars["groupname"]

	customLogger := logger.NewLoggerFromContext(r.Context()).WithField("groupname", group)

	vaultClient, rksErr := vault.NewVaultClientFromHTTPRequest(r)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	if exist, rksErr := vaultClient.GroupExists(group); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	} else if !exist {
		(&model.RksError{WrappedError: nil, Message: "Group not found", Code: 404}).HandleErr(r.Context(), w)
		return
	}

	//Read Group token in vault
	groupToken, rksErr := vaultClient.ReadGroupToken(group)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	if rksErr = vaultClient.DeleteGroupTokenAndPolicies(group, groupToken); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	if rksErr := vaultClient.DeleteConfig(group); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	if rksErr := vaultClient.DeleteGroupToken(group); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	if rksErr := vaultClient.PurgeGroupSecretList(group); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	logger.WithResponseStatus(customLogger, w).Info("deleted group")
}

func CreateSecret(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fqdn := vars["fqdn"]

	customLogger := logger.NewLoggerFromContext(r.Context()).WithField("fqdn", fqdn)

	vaultClient, err := vault.NewVaultClientFromHTTPRequest(r)
	if err != nil {
		err.HandleErr(r.Context(), w)
		return
	}

	secret := model.Secret{}
	if err := utils.DecodeHTTPJSONBodyToStruct(r, &secret); err != nil {
		err.HandleErr(r.Context(), w)
		return
	}

	if exists, rksErr := vaultClient.SecretExists(fqdn); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	} else if exists {
		(&model.RksError{WrappedError: nil, Message: "secret already exist", Code: 409}).HandleErr(r.Context(), w)
		return
	}

	if err := vaultClient.WriteSecret(fqdn, &secret); err != nil {
		err.HandleErr(r.Context(), w)
		return
	}

	w.WriteHeader(http.StatusCreated)
	logger.WithResponseStatus(customLogger, w).Info("created secret")
}

func UpdateSecret(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fqdn := vars["fqdn"]

	customLogger := logger.NewLoggerFromContext(r.Context()).WithField("fqdn", fqdn)

	vaultClient, err := vault.NewVaultClientFromHTTPRequest(r)
	if err != nil {
		err.HandleErr(r.Context(), w)
		return
	}

	if exists, rksErr := vaultClient.SecretExists(fqdn); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	} else if !exists {
		(&model.RksError{WrappedError: nil, Message: "secret does not exist", Code: 404}).HandleErr(r.Context(), w)
		return
	}

	secret := model.Secret{}
	if err := utils.DecodeHTTPJSONBodyToStruct(r, &secret); err != nil {
		err.HandleErr(r.Context(), w)
		return
	}

	if err := vaultClient.WriteSecret(fqdn, &secret); err != nil {
		err.HandleErr(r.Context(), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	logger.WithResponseStatus(customLogger, w).Info("updated secret")
}

func DeleteSecret(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fqdn := vars["fqdn"]

	customLogger := logger.NewLoggerFromContext(r.Context()).WithField("fqdn", fqdn)

	vaultClient, err := vault.NewVaultClientFromHTTPRequest(r)
	if err != nil {
		err.HandleErr(r.Context(), w)
		return
	}

	if exists, rksErr := vaultClient.SecretExists(fqdn); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	} else if !exists {
		(&model.RksError{WrappedError: nil, Message: "Secret not found", Code: 404}).HandleErr(r.Context(), w)
		return
	}

	if groupsSecret, rksErr := vaultClient.GetSecretGroupList(fqdn); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	} else if len(groupsSecret) > 0 {
		(&model.RksError{WrappedError: nil, Message: fqdn + "still associated to at least one group", Code: 409}).HandleErr(r.Context(), w)
		return
	}

	if err := vaultClient.PurgeKey(fqdn); err != nil {
		err.HandleErr(r.Context(), w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	logger.WithResponseStatus(customLogger, w).Info("deleted secret")
}

func GetGroupSecrets(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	group := vars["groupname"]

	customLogger := logger.NewLoggerFromContext(r.Context()).WithField("groupname", group)

	vaultClient, err := vault.NewVaultClientFromHTTPRequest(r)
	if err != nil {
		err.HandleErr(r.Context(), w)
		return
	}

	if exists, rksErr := vaultClient.GroupExists(group); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	} else if !exists {
		(&model.RksError{WrappedError: nil, Message: "Group not found", Code: 404}).HandleErr(r.Context(), w)
		return
	}

	groupSecrets, err := vaultClient.GetGroupSecretList(group)
	if err != nil {
		err.HandleErr(r.Context(), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	if err := utils.WriteStructAsJSON(w, groupSecrets.Secrets); err != nil {
		err.HandleErr(r.Context(), w)
		return
	}
	logger.WithResponseStatus(customLogger, w).Info("get groupsecrets")
}

func AssociateSecret(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	group := vars["groupname"]
	fqdn := vars["fqdn"]

	customLogger := logger.NewLoggerFromContext(r.Context()).WithFields(log.Fields{"groupname": group, "fqdn": fqdn})

	vaultClient, rksErr := vault.NewVaultClientFromHTTPRequest(r)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	if exists, rksErr := vaultClient.SecretExists(fqdn); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	} else if !exists {
		(&model.RksError{WrappedError: nil, Message: "Secret not found", Code: 404}).HandleErr(r.Context(), w)
		return
	}

	if exists, rksErr := vaultClient.GroupExists(group); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	} else if !exists {
		(&model.RksError{WrappedError: nil, Message: "Group not found", Code: 404}).HandleErr(r.Context(), w)
		return
	}

	groupSecrets, rksErr := vaultClient.GetGroupSecretList(group)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	for _, secret := range groupSecrets.Secrets {
		if secret == fqdn {
			(&model.RksError{WrappedError: nil, Message: fqdn + "already associated to " + group, Code: 409}).HandleErr(r.Context(), w)
			return
		}
	}

	groupSecrets.Secrets = append(groupSecrets.Secrets, fqdn)
	sort.Strings(groupSecrets.Secrets)

	if rksErr := vaultClient.WriteGroupSecretList(group, groupSecrets); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	policy, err := utils.UpdateTemplatedPolicy(vault.GroupSecretAccessPolicy, groupSecrets.Secrets)
	if err != nil {
		(&model.RksError{WrappedError: err, Message: "couldn't update group secret access policy", Code: 500}).HandleErr(r.Context(), w)
		return
	}

	err = vaultClient.Sys().PutPolicy(group, policy)
	if err != nil {
		log.Fatal(err)
	}
	w.WriteHeader(http.StatusOK)
	logger.WithResponseStatus(customLogger, w).Info("associate secret")
}

func DissociateSecret(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	group := vars["groupname"]
	fqdn := vars["fqdn"]

	customLogger := logger.NewLoggerFromContext(r.Context()).WithFields(log.Fields{"groupname": group, "fqdn": fqdn})

	vaultClient, rksErr := vault.NewVaultClientFromHTTPRequest(r)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	if exists, rksErr := vaultClient.GroupExists(group); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	} else if !exists {
		(&model.RksError{WrappedError: nil, Message: "Group not found", Code: 404}).HandleErr(r.Context(), w)
		return
	}

	if exists, rksErr := vaultClient.SecretExists(fqdn); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	} else if !exists {
		(&model.RksError{WrappedError: nil, Message: "Secret not found", Code: 404}).HandleErr(r.Context(), w)
		return
	}

	groupSecrets, rksErr := vaultClient.GetGroupSecretList(group)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	found := false
	for _, secret := range groupSecrets.Secrets {
		if secret == fqdn {
			found = true
		}
	}
	if found {
		fqdnIndex := sort.SearchStrings(groupSecrets.Secrets, fqdn)
		groupSecrets.Secrets = append(groupSecrets.Secrets[:fqdnIndex], groupSecrets.Secrets[fqdnIndex+1:]...)
	}

	if rksErr := vaultClient.WriteGroupSecretList(group, groupSecrets); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	policy, err := utils.UpdateTemplatedPolicy(vault.GroupSecretAccessPolicy, groupSecrets.Secrets)
	if err != nil {
		(&model.RksError{WrappedError: err, Message: "couldn't update group secret access policy", Code: 500}).HandleErr(r.Context(), w)
		return
	}

	err = vaultClient.Sys().PutPolicy(group, policy)
	if err != nil {
		log.Println(err)
	}
	w.WriteHeader(http.StatusNoContent)
	logger.WithResponseStatus(customLogger, w).Info("dissociate secret")
}

func GetSecretGroups(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fqdn := vars["fqdn"]

	customLogger := logger.NewLoggerFromContext(r.Context()).WithField("fqdn", fqdn)

	vaultClient, rksErr := vault.NewVaultClientFromHTTPRequest(r)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	if exists, rksErr := vaultClient.SecretExists(fqdn); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	} else if !exists {
		(&model.RksError{WrappedError: nil, Message: "Secret not found", Code: 404}).HandleErr(r.Context(), w)
		return
	}

	groupResList, rksErr := vaultClient.GetSecretGroupList(fqdn)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	if err := utils.WriteStructAsJSON(w, groupResList); err != nil {
		err.HandleErr(r.Context(), w)
		return
	}
	logger.WithResponseStatus(customLogger, w).Info("get secret groups")
}

func GetGroupToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	group := vars["groupname"]

	customLogger := logger.NewLoggerFromContext(r.Context()).WithField("groupname", group)

	vaultClient, err := vault.NewVaultClientFromHTTPRequest(r)
	if err != nil {
		err.HandleErr(r.Context(), w)
		return
	}

	if exists, rksErr := vaultClient.GroupExists(group); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	} else if !exists {
		(&model.RksError{WrappedError: nil, Message: "Group not found", Code: 404}).HandleErr(r.Context(), w)
		return
	}

	groupToken, rksErr := vaultClient.ReadGroupToken(group)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	if err := utils.WriteStructAsJSON(w, groupToken); err != nil {
		err.HandleErr(r.Context(), w)
		return
	}
	logger.WithResponseStatus(customLogger, w).Info("get group token")
}

func UpdateGroupToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	group := vars["groupname"]

	customLogger := logger.NewLoggerFromContext(r.Context()).WithField("groupname", group)

	vaultClient, err := vault.NewVaultClientFromHTTPRequest(r)
	if err != nil {
		err.HandleErr(r.Context(), w)
		return
	}

	if exists, rksErr := vaultClient.GroupExists(group); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	} else if !exists {
		(&model.RksError{WrappedError: nil, Message: "Group not found", Code: 404}).HandleErr(r.Context(), w)
		return
	}

	groupToken, rksErr := vaultClient.ReadGroupToken(group)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	newGroupToken, rksErr := vaultClient.CreateGroupToken(group)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}
	//revoke old grouptoken (and all tree of nodeToken!
	if rksErr := vaultClient.RevokeGroupToken(groupToken); err != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	//delete old grouptoken from group
	if rksErr := vaultClient.DeleteGroupToken(group); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	//write new grouptoken for group
	if rksErr := vaultClient.WriteGroupToken(group, groupToken); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	if err := utils.WriteStructAsJSON(w, newGroupToken); err != nil {
		err.HandleErr(r.Context(), w)
		return
	}
	logger.WithResponseStatus(customLogger, w).Info("update group token")
}

func GetGroupConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	group := vars["groupname"]

	customLogger := logger.NewLoggerFromContext(r.Context()).WithField("groupname", group)

	vaultClient, err := vault.NewVaultClientFromHTTPRequest(r)
	if err != nil {
		err.HandleErr(r.Context(), w)
		return
	}

	if exists, rksErr := vaultClient.GroupExists(group); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	} else if !exists {
		(&model.RksError{WrappedError: nil, Message: "Group not found", Code: 404}).HandleErr(r.Context(), w)
		return
	}

	groupConfig, rksErr := vaultClient.ReadGroupConfig(group)
	if rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	if rksErr := utils.WriteStructAsJSON(w, groupConfig); rksErr != nil {
		rksErr.HandleErr(r.Context(), w)
		return
	}
	logger.WithResponseStatus(customLogger, w).Info("get group config")
}

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

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Orange-OpenSource/remote-key-server/pkg/logger"
	"github.com/Orange-OpenSource/remote-key-server/pkg/model"
	"github.com/Orange-OpenSource/remote-key-server/pkg/utils"
	vaultAPI "github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

// Configuration options
type Configuration struct {
	VaultAddr        string
	Certificate      string
	PrivateKey       string
	ListenAddress    string
	VaultInitialized bool
	AdminLogin       string
	AdminPwd         string
}

// Configs the global config struct
var Config Configuration

type VaultOption func(v *Vault)

type Vault struct {
	*vaultAPI.Client
	logger logrus.FieldLogger
	//	casOpt int
}

func NewVaultClient(ctx context.Context, token string) (*Vault, *model.RksError) {
	vaultClient, err := vaultAPI.NewClient(vaultAPI.DefaultConfig())
	if err != nil {
		return nil, &model.RksError{WrappedError: err, Message: "Unable to get VaultClient ", Code: 500}
	}

	err = vaultClient.SetAddress(Config.VaultAddr)
	if err != nil {
		return nil, &model.RksError{WrappedError: err, Message: "Unable to set vault address", Code: 500}
	}

	vaultClient.SetToken(token)

	vc := &Vault{Client: vaultClient, logger: logger.NewLoggerFromContext(ctx)}

	//	for _, opt := range opts {
	//		opt(vc)
	//	}

	return vc, nil
}

func NewVaultClientFromHTTPRequest(r *http.Request) (*Vault, *model.RksError) {
	token := r.Header.Get("X-Vault-Token")
	if token == "" {
		return nil, &model.RksError{WrappedError: nil, Message: "X-Vault-Token not found", Code: 403}
	}

	return NewVaultClient(r.Context(), token)
}

func RKSErrFromVaultErr(err error, msg string) *model.RksError {
	// We are interested only in an unauthorized error, indicating that given token is invalid
	if vaultErr, ok := err.(*vaultAPI.ResponseError); ok && vaultErr.StatusCode == 403 {
		return &model.RksError{WrappedError: vaultErr, Message: msg + ": vault unauthorized", Code: 403}
	}
	return &model.RksError{WrappedError: err, Message: msg + ": vault internal error", Code: 500}
}

func (v *Vault) ReadSecret(path string) (*vaultAPI.Secret, *model.RksError) {
	vaultSecret, vaultErr := v.Logical().Read(path)
	if vaultErr != nil {
		return nil, RKSErrFromVaultErr(vaultErr, "read secret")
	}

	return vaultSecret, nil
}

// ReadSecretIntoStruct read key at *path* and decodes vault secret "data" field into given data struct
// This function will fail if no vault secret is found
func (v *Vault) ReadSecretIntoStruct(path string, data interface{}) *model.RksError {
	vaultSecret, rksErr := v.ReadSecret(path)
	if rksErr != nil {
		return rksErr
	}
	if vaultSecret == nil {
		return &model.RksError{WrappedError: nil, Message: "vault secret not found", Code: 404}
	}

	if err := mapstructure.Decode(vaultSecret.Data["data"], data); err != nil {
		return &model.RksError{WrappedError: err, Message: "failed to decode data from Vault in given struct", Code: 500}
	}
	return nil
}

func (v *Vault) ReadSecretIntoStructWithCas(path string, data interface{}) (int, *model.RksError) {
	vaultSecret, rksErr := v.ReadSecret(path)
	if rksErr != nil {
		return 0, rksErr
	}
	if vaultSecret == nil {
		return 0, &model.RksError{WrappedError: nil, Message: "vault secret not found", Code: 404}
	}

	if err := mapstructure.Decode(vaultSecret.Data["data"], data); err != nil {
		return 0, &model.RksError{WrappedError: err, Message: "failed to decode data from Vault in given struct", Code: 500}
	}

	metadata, ok := vaultSecret.Data["metadata"].(map[string]interface{})
	if !ok {
		return 0, &model.RksError{WrappedError: nil, Message: "failed to decode metadata from Vault ", Code: 500}

	}
	versionjson, ok := metadata["version"].(json.Number)
	if !ok {
		return 0, &model.RksError{WrappedError: nil, Message: "failed to decode versionjson from metadata from Vault ", Code: 500}

	}
	version, err := versionjson.Int64()
	if err != nil {
		return 0, &model.RksError{WrappedError: nil, Message: "failed to decode version from metadata from Vault ", Code: 500}

	}
	return int(version), nil
}

func (v *Vault) WriteStruct(path string, data interface{}) *model.RksError {
	vaultData := make(map[string]interface{})

	err := mapstructure.Decode(data, &vaultData)
	if err != nil {
		return &model.RksError{WrappedError: err, Message: "failed to write data struct in vault map", Code: 500}
	}
	_, err = v.Logical().Write(path, map[string]interface{}{"data": vaultData})
	if err != nil {
		return RKSErrFromVaultErr(err, "write struct")
	}
	return nil
}

func (v *Vault) WriteStructWithCas(path string, data interface{}, version int) *model.RksError {
	vaultData := make(map[string]interface{})

	err := mapstructure.Decode(data, &vaultData)
	if err != nil {
		return &model.RksError{WrappedError: err, Message: "failed to write data struct in vault map", Code: 500}
	}
	options := map[string]interface{}{
		"cas": version,
	}
	_, err = v.Logical().Write(path, map[string]interface{}{"data": vaultData, "options": options})
	if err != nil {
		return RKSErrFromVaultErr(err, "write struct")
	}

	return nil
}
func (v *Vault) KeyExists(path string) (bool, *model.RksError) {
	vaultSecret, rksErr := v.ReadSecret(path)
	if rksErr != nil {
		return false, rksErr
	}
	if vaultSecret != nil {
		return true, nil
	}
	return false, nil
}

// PurgeKey removes a key entirely
// Vault KV2 introduces new semantics to delete with possibility to remove specific version of a key/value
// We want a complete key/value deletion so we use rks/metadata/fqdn
// https://www.vaultproject.io/api/secret/kv/kv-v2.html#delete-metadata-and-all-versions
func (v *Vault) PurgeKey(path string) *model.RksError {
	_, err := v.Logical().Delete("rks/metadata/" + path)
	if err != nil {
		return RKSErrFromVaultErr(err, "failed to delete secret into vault")
	}
	return nil
}

//List first stage of path under given path
//remove / at end of key if exists
func (v *Vault) ListKeysUnderPath(path string) ([]string, *model.RksError) {
	secret, err := v.Logical().List("rks/metadata/" + path)
	if err != nil {
		return nil, RKSErrFromVaultErr(err, "failed to list secret into vault")
	}
	res := []string{}
	if secret != nil {
		tmp, ok := secret.Data["keys"].([]interface{})
		if !ok {
			return nil, &model.RksError{WrappedError: nil, Message: "unexpected vault secret format returned", Code: 500}
		}
		var tmp1 string
		for _, groupname := range tmp {
			tmp1 = groupname.(string)
			if strings.HasSuffix(tmp1, "/") {
				res = append(res, tmp1[:len(tmp1)-1])
			} else {
				res = append(res, tmp1)
			}
		}
	}
	return res, nil
}

func (v *Vault) GetGroupNameFromGroupToken() (string, *model.RksError) {
	secret, err := v.Auth().Token().LookupSelf()
	if err != nil {
		return "", RKSErrFromVaultErr(err, "get groupname from grouptoken")
	}
	if secret == nil {
		return "", &model.RksError{Message: "get groupname from grouptoken, token lookup returned nothing", Code: 500}
	}

	metadata, err := secret.TokenMetadata()
	if err != nil {
		return "", RKSErrFromVaultErr(err, "get grouptoken metadata")
	}
	if metadata == nil {
		return "", &model.RksError{Message: "get groupname from grouptoken, token has no associated metadata, this token is not a grouptoken ", Code: 403}
	}

	group, ok := metadata["groupname"]
	if !ok {
		return "", &model.RksError{Message: "No groupname found in token metadata, this token is not a grouptoken", Code: 403}
	}
	return group, nil
}

func (v *Vault) GetGroupList() ([]string, *model.RksError) {
	groupnameList, rksErr := v.ListKeysUnderPath("groups")
	if rksErr != nil {
		return nil, rksErr
	}

	return groupnameList, nil
}

func (v *Vault) GetGroupSecretList(group string) (*model.GroupSecrets, int, *model.RksError) {
	groupSecrets := model.GroupSecrets{
		Secrets: []string{},
	}

	version := 0
	keyExists, err := v.KeyExists("rks/data/groups/" + group + "/secret-list")
	if err != nil {
		return nil, version, err
	}
	if keyExists {
		version, err = v.ReadSecretIntoStructWithCas("rks/data/groups/"+group+"/secret-list", &groupSecrets)
		if err != nil {
			return nil, version, err
		}
	}
	return &groupSecrets, version, nil
}

func (v *Vault) WriteGroupSecretList(group string, groupSecrets *model.GroupSecrets, version int) *model.RksError {
	if rksErr := v.WriteStructWithCas("rks/data/groups/"+group+"/secret-list", groupSecrets, version); rksErr != nil {
		return rksErr
	}
	return nil
}

func (v *Vault) PurgeGroupSecretList(group string) *model.RksError {
	if rksErr := v.PurgeKey("groups/" + group + "/secret-list"); rksErr != nil {
		return rksErr
	}
	return nil
}

//return a list of groupname that uses a secret
//return an empyt list if None
func (v *Vault) GetSecretGroupList(fqdn string) ([]string, *model.RksError) {
	//Get list of groupname
	groupnameList, rksErr := v.ListKeysUnderPath("groups")
	if rksErr != nil {
		return nil, rksErr
	}

	groupResList := []string{}

	for _, groupname := range groupnameList {
		groupSecrets, _, err := v.GetGroupSecretList(groupname)
		if err != nil {
			return nil, err
		}
		for _, secretfqdn := range groupSecrets.Secrets {
			if secretfqdn == fqdn {
				groupResList = append(groupResList, groupname)
			}
		}
	}
	return groupResList, nil
}

func (v *Vault) SecretExists(fqdn string) (bool, *model.RksError) {
	if keyExists, rksErr := v.KeyExists("rks/data/" + fqdn); rksErr != nil {
		return false, rksErr
	} else if !keyExists {
		return false, nil
		//&model.RksError{WrappedError: nil, Message: fqdn + " secret does not exist", Code: 404}
	}
	return true, nil
}

func (v *Vault) WriteSecret(fqdn string, secret *model.Secret) *model.RksError {
	if err := v.WriteStruct("rks/data/"+fqdn, secret.Data); err != nil {
		return err
	}
	return nil
}

func (v *Vault) GroupExists(group string) (bool, *model.RksError) {
	if groupExists, rksErr := v.KeyExists("rks/data/groups/" + group + "/config"); rksErr != nil {
		return false, rksErr
	} else if groupExists {
		return true, nil
	} else {
		return false, nil
	}
	// &model.RksError{Error: nil, Message: "Group Does not exists", Code: 404}
}

func (v *Vault) ReadGroupConfig(group string) (*model.GroupRegInfo, *model.RksError) {
	groupRegInfo := model.GroupRegInfo{}

	if rksErr := v.ReadSecretIntoStruct("rks/data/groups/"+group+"/config", &groupRegInfo); rksErr != nil {
		return nil, rksErr
	}

	return &groupRegInfo, nil
}

func (v *Vault) WriteGroupConfig(group string, groupRegInfo *model.GroupRegInfo) *model.RksError {
	if rksErr := v.WriteStruct("rks/data/groups/"+group+"/config", groupRegInfo); rksErr != nil {
		return rksErr
	}
	return nil
}

func (v *Vault) WriteGroupToken(group string, groupToken *model.GroupToken) *model.RksError {
	if rksErr := v.WriteStruct("rks/data/groups/"+group+"/grouptoken", groupToken); rksErr != nil {
		return rksErr
	}
	return nil
}

func (v *Vault) DeleteGroupToken(group string) *model.RksError {
	if rksErr := v.PurgeKey("groups/" + group + "/grouptoken"); rksErr != nil {
		return rksErr
	}
	return nil
}

func (v *Vault) ReadGroupToken(group string) (*model.GroupToken, *model.RksError) {
	groupToken := model.GroupToken{}

	if rksErr := v.ReadSecretIntoStruct("rks/data/groups/"+group+"/grouptoken", &groupToken); rksErr != nil {
		return nil, rksErr
	}

	return &groupToken, nil
}

func (v *Vault) CreateGroupTokenAndPolicies(group string) (*model.GroupToken, *model.RksError) {
	//CreateAddTokenRole Policy for this group
	policy, err := utils.UpdateTemplatedPolicy(GroupTokenAccessPolicy, group)
	if err != nil {
		return nil, &model.RksError{WrappedError: err, Message: "Unable to create group:issue while templating policy", Code: 500}
	}

	err = v.Sys().PutPolicy("addToken-"+group, policy)
	if err != nil {
		return nil, RKSErrFromVaultErr(err, "Unable to create group:issue while templating policy")
	}

	//Create <groupname> policy for future node-token from this group
	//this ensure nodetoken will be able to renew even if it has no secrets associated
	err = v.Sys().PutPolicy(group, GroupInitAccessPolicy)
	if err != nil {
		return nil, RKSErrFromVaultErr(err, "Unable to create group:issue while creating node policy")
	}

	//create role, to create group token
	if rksErr := v.CreateGroupTokenRole(group); rksErr != nil {
		return nil, rksErr
	}
	//create token with previous created role, no_default and orphan, with groupname in metadata, no_parent
	groupToken, rksErr := v.CreateGroupToken(group)
	if rksErr != nil {
		return nil, rksErr
	}

	return groupToken, nil
}

func (v *Vault) CreateGroupToken(group string) (*model.GroupToken, *model.RksError) {

	tokenCreateAPIRequest := vaultAPI.TokenCreateRequest{
		Metadata: map[string]string{"groupname": group},
	}

	secret, err := v.Auth().Token().CreateWithRole(&tokenCreateAPIRequest, "addToken-"+group)
	if err != nil {
		return nil, RKSErrFromVaultErr(err, fmt.Sprintf("Error while trying to create group %s: Unable to create grouptoken", group))
	}

	groupAuthToken := model.TokenAuth{}
	err = mapstructure.Decode(secret.Auth, &groupAuthToken)
	if err != nil {
		return nil, &model.RksError{WrappedError: err, Message: "Error while trying to create group: Failed to decode group token", Code: 500}
	}

	groupToken := model.GroupToken{GroupToken: groupAuthToken.ClientToken}

	return &groupToken, nil
}

func (v *Vault) DeleteGroupTokenAndPolicies(group string) *model.RksError {
	//Revoke All token created against group token roke, and all child (node token)
	if err := v.RevokeGroupToken(group); err != nil {
		return err
	}
	if err := v.Sys().DeletePolicy("addToken-" + group); err != nil {
		return RKSErrFromVaultErr(err, "Error while deleting group token policy")
	}

	if _, err := v.Logical().Delete("/auth/token/roles/addToken-" + group); err != nil {
		return RKSErrFromVaultErr(err, "Error while deleting group token role")
	}

	if err := v.Sys().DeletePolicy(group); err != nil {
		return RKSErrFromVaultErr(err, "Error while deleting node token policy")
	}
	return nil
}

func (v *Vault) RevokeGroupToken(group string) *model.RksError {
	url := fmt.Sprintf("/auth/token/create/addToken-%s", group)

	err := v.Sys().RevokePrefix(url)
	if err != nil {
		return RKSErrFromVaultErr(err, fmt.Sprintf("Couldn't Revoke Token for group %s ", group))
	}
	return nil
}

func (v *Vault) CreateGroupTokenRole(group string) *model.RksError {
	allowedPolicies := [1]string{"addToken-" + group}
	disallowedPolicies := [1]string{"admin"}
	url := fmt.Sprintf("/auth/token/roles/%s-%s", "addToken", group)

	_, err := v.Logical().Write(url, map[string]interface{}{
		"allowed_policies":        allowedPolicies,
		"disallowed_policies":     disallowedPolicies,
		"orphan":                  true,
		"token_no_default_policy": true,
		"period":                  "2678400", // 31 days
	})
	if err != nil {
		return RKSErrFromVaultErr(err, fmt.Sprintf("Couldn't create Token Role for groupname %s unable to create group ", group))
	}
	return nil
}

func (v *Vault) CreateNodeTokenRole(group string, nodeID string) *model.RksError {
	allowedPolicies := [1]string{group}
	disallowedPolicies := [1]string{"addToken-" + group}
	url := fmt.Sprintf("/auth/token/roles/%s-%s", group, nodeID)

	_, err := v.Logical().Write(url, map[string]interface{}{
		"allowed_policies":    allowedPolicies,
		"disallowed_policies": disallowedPolicies,
		//"period":              "2678400", // 31 days
		"period": "600", // 10 minutes
	})
	if err != nil {
		return RKSErrFromVaultErr(err, fmt.Sprintf("Couldn't create Token Role for node %s in groupname %s unable to register node ", nodeID, group))
	}
	return nil
}

func (v *Vault) RevokeNodeToken(group string, nodeID string) *model.RksError {
	url := fmt.Sprintf("/auth/token/create/%s-%s", group, nodeID)

	err := v.Sys().RevokePrefix(url)
	if err != nil {
		return RKSErrFromVaultErr(err, fmt.Sprintf("Couldn't Revoke Token for node %s in groupname %s unable to register node ", nodeID, group))
	}
	return nil
}

func (v *Vault) CreateNodeTokenFromRole(group string, nodeID string) (*vaultAPI.Secret, *model.RksError) {
	url := fmt.Sprintf("/auth/token/create/%s-%s", group, nodeID)
	auth, err := v.Logical().Write(url, map[string]interface{}{})
	if err != nil {
		return nil, RKSErrFromVaultErr(err, "Error while trying to create Token , unable to register Node")
	}
	if auth == nil {
		return nil, &model.RksError{WrappedError: err, Message: fmt.Sprintf("Couldn't create Token for node %s in group %s, unable to register node", nodeID, group), Code: 500}
	}
	return auth, nil
}

func (v *Vault) ConfigExists() (bool, *model.RksError) {
	if configExists, rksErr := v.KeyExists("rks/data/config"); rksErr != nil {
		return false, rksErr
	} else if !configExists {
		return false, nil
	}
	return true, nil
}

func (v *Vault) WriteConfig() *model.RksError {
	if err := v.WriteStruct("rks/data/config", Config); err != nil {
		return err
	}
	return nil
}

func (v *Vault) DeleteConfig(group string) *model.RksError {
	if rksErr := v.PurgeKey("groups/" + group + "/config"); rksErr != nil {
		return rksErr
	}
	return nil
}

func (v *Vault) InitKvBackend() *model.RksError {
	if err := v.Sys().Mount("rks",
		&vaultAPI.MountInput{
			Type:    "kv",
			Options: map[string]string{"version": "2"},
		},
	); err != nil {
		return RKSErrFromVaultErr(err, "init kv backend")
	}
	return nil
}

func (v *Vault) EnableAdminUserpassBackend() *model.RksError {
	if err := v.Sys().EnableAuthWithOptions(
		"userpass",
		&vaultAPI.MountInput{
			Type:        "userpass",
			Description: "RKS login with user/password for admin and group managers"},
	); err != nil {
		return RKSErrFromVaultErr(err, "failed to mount Vault user password auth")
	}
	if err := v.Sys().PutPolicy("admin", AdminPolicy); err != nil {
		return RKSErrFromVaultErr(err, "failed to create admin policy")
	}

	policies := []string{"admin"}
	options := map[string]interface{}{
		"password":       Config.AdminPwd,
		"policies":       policies,
		"token_policies": policies,
	}

	path := fmt.Sprintf("auth/userpass/users/%s", Config.AdminLogin)

	if _, err := v.Logical().Write(path, options); err != nil {
		return RKSErrFromVaultErr(err, "failed to create admin user into vault")
	}
	return nil
}

func (v *Vault) Login(login string, adminPassword string) (*model.AdminToken, *model.RksError) {
	path := fmt.Sprintf("auth/userpass/login/%s", login)
	options := map[string]interface{}{
		"password": adminPassword,
	}

	secret, err := v.Logical().Write(path, options)
	if err != nil {
		vaultErr, ok := err.(*vaultAPI.ResponseError)
		if ok && vaultErr.StatusCode == 400 {
			return nil, &model.RksError{WrappedError: vaultErr, Message: "bad login or password", Code: 400}
		}
		return nil, RKSErrFromVaultErr(err, "failed to login")
	}

	adminAuthToken := model.TokenAuth{}
	err = mapstructure.Decode(secret.Auth, &adminAuthToken)
	if err != nil {
		return nil, &model.RksError{WrappedError: err, Message: "Error while trying to decode token after login", Code: 500}
	}

	adminToken := model.AdminToken{AdminToken: adminAuthToken.ClientToken}

	return &adminToken, nil
}

// recursively delete all secrets under a path
//func (v *Vault) PurgePath(rootPath string) *model.RksError {
//	child_paths, err := v.APIClient.Logical().List(rootPath)
//	if err != nil {
//		(&model.RksError{Error:err,Message:"failed to delete secret into vault",Code:500}).HandleErr(r.Context(), w)
//	}
//
//	_, err := v.APIClient.Logical().Delete("rks/metadata/" + path)
//	if err != nil {
//		(&model.RksError{Error:err,Message:"failed to delete secret into vault",Code:500}).HandleErr(r.Context(), w)
//	}
//
//	return nil
// }

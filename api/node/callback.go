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
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/Orange-OpenSource/remote-key-server/logger"
	"github.com/Orange-OpenSource/remote-key-server/model"
)

// Anonymous structure to decode json response and get oAuth access_token
type OAuthResponse struct {
	AccessToken string `json:"access_token"`
}

func GetHttpClient(insecure bool) *http.Client {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
	}
	return &http.Client{Transport: tr}
}

func OAuthCallback(ctx context.Context, httpClient *http.Client, groupRegInfo *model.GroupRegInfo) (*OAuthResponse, *model.RksError) {
	customLogger := logger.NewLoggerFromContext(ctx)
	oauthReq, err := http.NewRequest("POST", groupRegInfo.OauthURL, nil)
	if err != nil {
		errMsg := fmt.Sprintf("error while building request to oauth to get allowed Node ")
		return nil, &model.RksError{WrappedError: err, Message: errMsg, Code: 500}
	}

	oauthReq.SetBasicAuth(groupRegInfo.OauthClientID, groupRegInfo.OauthClientSecret)
	q := oauthReq.URL.Query()
	q.Add("client_id", groupRegInfo.OauthClientID)
	q.Add("client_secret", groupRegInfo.OauthClientSecret)
	q.Add("grant_type", "client_credentials")
	oauthReq.URL.RawQuery = q.Encode()

	customLogger.WithFields(logrus.Fields{"oauth_client_id": groupRegInfo.OauthClientID, "oauth_client_secret": groupRegInfo.OauthClientSecret, "oauth_url": groupRegInfo.OauthURL}).Debug("query callback URL for authorization")
	resp, err := httpClient.Do(oauthReq)
	if err != nil {
		return nil, &model.RksError{WrappedError: err, Message: "http oauth request failed", Code: 500}
	}
	if resp.StatusCode == 401 {
		return nil, &model.RksError{WrappedError: err, Message: "http oauth request failed, 401 from Callback server", Code: 500}
	}
	defer resp.Body.Close()

	oauthResponse := OAuthResponse{}
	decoder := json.NewDecoder(resp.Body)

	err = decoder.Decode(&oauthResponse)

	if err != nil {
		return nil, &model.RksError{WrappedError: err, Message: "http oauthrequest failed, failed to decode OAuth response", Code: 500}
	}

	customLogger.WithField("oauth_access_token", oauthResponse.AccessToken).Debug("succesfully got an access_token from oauth callback url")

	return &oauthResponse, nil
}

func Callback(ctx context.Context, groupRegInfo *model.GroupRegInfo, nodeID string) *model.RksError {
	customLogger := logger.NewLoggerFromContext(ctx)
	// First get callback URL authentication token using oAuth
	httpClient := GetHttpClient(true)
	oauthResponse, rksErr := OAuthCallback(ctx, httpClient, groupRegInfo)
	if rksErr != nil {
		return rksErr
	}

	url := fmt.Sprintf("%s/%s", groupRegInfo.CallbackURL, nodeID)
	customLogger.WithField("constructed_callback_url", url).Debug("request callback url for node autorization")

	// We got oAuth access token, now query callback URL
	nodeAllowedReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		errMsg := fmt.Sprintf("Error while building request to callbackurl to get allowed Node %s", nodeID)
		return &model.RksError{WrappedError: err, Message: errMsg, Code: 500}
	}

	// Remove double dashes in URL in case callback URL does contain an ending /
	nodeAllowedReq.URL.Path = strings.Replace(nodeAllowedReq.URL.Path, "//", "/", -1)
	nodeAllowedReq.Header.Set("Authorization", "Bearer "+oauthResponse.AccessToken)

	nodeAllowedResp, err := httpClient.Do(nodeAllowedReq)
	if err != nil {
		errMsg := fmt.Sprintf("Allowed Node request error for Node: %s", nodeID)
		return &model.RksError{WrappedError: err, Message: errMsg, Code: 500}
	}
	defer nodeAllowedResp.Body.Close()

	customLogger.WithField("callback_status", nodeAllowedResp.StatusCode).Debug("queried callback url")

	switch nodeAllowedResp.StatusCode {
	case 403:
		errMsg := fmt.Sprintf("node %s not Allowed", nodeID)
		return &model.RksError{WrappedError: nil, Message: errMsg, Code: 403}
	case 404:
		errMsg := fmt.Sprintf("node %s not found", nodeID)
		return &model.RksError{WrappedError: nil, Message: errMsg, Code: 403}
	case 200:
		break
	default:
		errMsg := fmt.Sprintf("unknown error returned by callback url when asking if node %s is allowed", nodeID)
		return &model.RksError{WrappedError: nil, Message: errMsg, Code: 500}
	}

	return nil
}

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
package api

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/Orange-OpenSource/remote-key-server/pkg/api/admin"
	"github.com/Orange-OpenSource/remote-key-server/pkg/api/initialize"
	"github.com/Orange-OpenSource/remote-key-server/pkg/api/node"
	"github.com/Orange-OpenSource/remote-key-server/pkg/api/secret"
	"github.com/Orange-OpenSource/remote-key-server/pkg/model"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

func ContentEncodingCheckerMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentEncoding := strings.ToLower(r.Header.Get("Content-Encoding"))
		if (contentEncoding != "") && (contentEncoding != "identity") {
			rksErr := model.RksError{WrappedError: nil, Message: "Content-Encoding Header not valid", Code: 400}
			rksErr.HandleErr(r.Context(), w)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

func ContentTypeCheckerMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Method == "POST" || r.Method == "PUT") && HasJSONBody(r) {
			contentType := strings.ToLower(r.Header.Get("Content-Type"))
			if contentType != "application/json" {
				rksErr := model.RksError{WrappedError: nil, Message: "Content-Type Header not valid", Code: 415}
				rksErr.HandleErr(r.Context(), w)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// HasJSONBody checks if the provided request has a Body
// A Go internal HTTP/2 bug results in a body non nil and non equals to http.NoBody in the http request
// Therefore we need to check if the given body is empty or not
// To do that we try to read one byte from the body and check if we have io.EOF
// If we read a byte, we read the rest of the body and recompose one with the first byte and the rest
func HasJSONBody(r *http.Request) bool {
	if r.Body == nil || r.Body == http.NoBody {
		return false
	}

	// Read first body byte
	firstByte := make([]byte, 1)
	_, err := io.ReadFull(r.Body, firstByte)
	if err == io.EOF { // No byte to read => No body
		return false
	} else if err != nil {
		logrus.Error(err)
		return true
	}

	// If we have a body we must rebuild one for the next gorilla route matcher
	// We read the rest of the body
	restOfBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logrus.Error(err)
		return true
	}
	logrus.Info("Body:", string(restOfBody))
	r.Body.Close() // must close once read

	r.Body = ioutil.NopCloser(io.MultiReader(bytes.NewBuffer(firstByte), bytes.NewBuffer(restOfBody))) // Recompose body from the first byte read and the rest of the body

	return true
}

func NewApiRouter(baseRouter *mux.Router) {
	router := baseRouter
	for key, route := range routes {
		handler := route.HandlerFunc

		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(key).
			Handler(handler)
	}
}

func Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "RKS API")
}

type Route struct {
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

var routes = map[string]Route{
	"Index": {
		"GET", "/", Index,
	},
	"Login": {
		"POST", "/rks/v1/admin/login", admin.Login,
	},
	"AssociateSecret": {
		"POST", "/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}/secrets/{fqdn}", admin.AssociateSecret,
	},
	"CreateGroup": {
		"POST", "/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}", admin.CreateGroup,
	},
	"GetGroup": {
		"GET", "/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}", admin.GetGroup,
	},
	"UpdateGroup": {
		"PUT", "/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}", admin.UpdateGroup,
	},
	"CreateSecret": {
		"POST", "/rks/v1/secret/{fqdn}", admin.CreateSecret,
	},
	"DeleteGroup": {
		"DELETE", "/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}", admin.DeleteGroup,
	},
	"DeleteSecret": {
		"DELETE", "/rks/v1/secret/{fqdn}", admin.DeleteSecret,
	},
	"DissociateSecret": {
		"DELETE", "/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}/secrets/{fqdn}", admin.DissociateSecret,
	},
	"GetGroupConfig": {
		"GET", "/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}/config", admin.GetGroupConfig,
	},
	"GetGroupSecrets": {
		"GET", "/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}/secrets", admin.GetGroupSecrets,
	},
	"GetGroupToken": {
		"GET", "/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}/grouptoken", admin.GetGroupToken,
	},
	"UpdateGroupToken": {
		"PUT", "/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}/grouptoken", admin.UpdateGroupToken,
	},
	"GetSecretGroups": {
		"GET", "/rks/v1/secret/{fqdn}/groups", admin.GetSecretGroups,
	},
	"InitRKS": {
		"POST", "/rks/v1/init", initialize.InitRKS,
	},
	"GetSecret": {
		"GET", "/rks/v1/secret/{fqdn}", secret.GetSecret,
	},
	"UpdateSecret": {
		"PUT", "/rks/v1/secret/{fqdn}", admin.UpdateSecret,
	},
	"RenewToken": {
		"POST", "/rks/v1/auth/token/renew-self", node.RenewToken,
	},
	"RegisterNode": {
		"POST", "/rks/v1/node", node.RegisterNode,
	},
	"RevokeNode": {
		"DELETE", "/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}/nodes/{nodeId}", admin.RevokeNode,
	},
}

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
		if (r.Method == "POST" || r.Method == "PUT") && HasJsonBody(r) {
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

func HasJsonBody(r *http.Request) bool {

	if r.Body == nil || r.Body == http.NoBody {
		return false
	}

	// Read first body byte
	firstByte := make([]byte, 1)
	_, err := io.ReadFull(r.Body, firstByte)
	if err == io.EOF { // No byte to read => No body
		return false
	} else if err != nil {
		return true
	}

	// If we have a body we must rebuild one for the next gorilla route matcher
	// We read the rest of the body
	restOfBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return true
	}
	r.Body.Close() // must close once read

	r.Body = ioutil.NopCloser(io.MultiReader(bytes.NewBuffer(firstByte), bytes.NewBuffer(restOfBody))) // Recompose body from the first byte read and the rest of the body

	return true
}

// disallow body in requests who don't need it (according to the specs)
// A HTTP/2 bug results in a body non nil and non equals to http.NoBody in the http request
// Therefore we need to check if the given body is empty or not
// To do that we try to read one byte from the body and check if we have io.EOF
func RouteWithoutJsonBody(r *http.Request, rm *mux.RouteMatch) bool {

	return !HasJsonBody(r)

}

func RouteWithJsonBody(r *http.Request, rm *mux.RouteMatch) bool {
	return !RouteWithoutJsonBody(r, rm)
}

func NewApiRouter(baseRouter *mux.Router) {
	router := baseRouter
	for key, route := range routes {
		handler := route.HandlerFunc

		if route.NeedJsonBody {
			router.
				Methods(route.Method).
				Path(route.Pattern).
				MatcherFunc(RouteWithJsonBody).
				Name(key).
				Handler(handler)
		} else {
			router.
				Methods(route.Method).
				Path(route.Pattern).
				MatcherFunc(RouteWithoutJsonBody).
				Name(key).
				Handler(handler)
		}
	}
}

func Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "RKS API")
}

type Route struct {
	Method       string
	Pattern      string
	NeedJsonBody bool
	HandlerFunc  http.HandlerFunc
}

var routes = map[string]Route{"Index": {"GET", "/", false, Index}, "Login": {
	strings.ToUpper("Post"),
	"/rks/v1/admin/login",
	true,
	admin.Login,
},
	"AssociateSecret": {
		strings.ToUpper("Post"),
		"/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}/secrets/{fqdn}",
		false,
		admin.AssociateSecret,
	},
	"CreateGroup": {
		strings.ToUpper("Post"),
		"/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}",
		true,
		admin.CreateGroup,
	},
	"GetGroup": {
		strings.ToUpper("Get"),
		"/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}",
		false,
		admin.GetGroup,
	},
	"UpdateGroup": {
		strings.ToUpper("Put"),
		"/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}",
		true,
		admin.UpdateGroup,
	},
	"CreateSecret": {
		strings.ToUpper("Post"),
		"/rks/v1/secret/{fqdn}",
		true,
		admin.CreateSecret,
	},
	"DeleteGroup": {
		strings.ToUpper("Delete"),
		"/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}",
		false,
		admin.DeleteGroup,
	},
	"DeleteSecret": {
		strings.ToUpper("Delete"),
		"/rks/v1/secret/{fqdn}",
		false,
		admin.DeleteSecret,
	},
	"DissociateSecret": {
		strings.ToUpper("Delete"),
		"/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}/secrets/{fqdn}",
		false,
		admin.DissociateSecret,
	},
	"GetGroupConfig": {
		strings.ToUpper("Get"),
		"/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}/config",
		false,
		admin.GetGroupConfig,
	},
	"GetGroupSecrets": {
		strings.ToUpper("Get"),
		"/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}/secrets",
		false,
		admin.GetGroupSecrets,
	},
	"GetGroupToken": {
		strings.ToUpper("Get"),
		"/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}/grouptoken",
		false,
		admin.GetGroupToken,
	},
	"UpdateGroupToken": {
		strings.ToUpper("Put"),
		"/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}/grouptoken",
		false,
		admin.UpdateGroupToken,
	},
	"GetSecretGroups": {
		strings.ToUpper("Get"),
		"/rks/v1/secret/{fqdn}/groups",
		false,
		admin.GetSecretGroups,
	},
	"InitRKS": {
		strings.ToUpper("Post"),
		"/rks/v1/init",
		false,
		initialize.InitRKS,
	},
	"GetSecret": {
		strings.ToUpper("Get"),
		"/rks/v1/secret/{fqdn}",
		false,
		secret.GetSecret,
	},
	"UpdateSecret": {
		strings.ToUpper("Put"),
		"/rks/v1/secret/{fqdn}",
		true,
		admin.UpdateSecret,
	},
	"RenewToken": {
		strings.ToUpper("Post"),
		"/rks/v1/auth/token/renew-self",
		false,
		node.RenewToken,
	},
	"RegisterNode": {
		strings.ToUpper("Post"),
		"/rks/v1/node",
		false,
		node.RegisterNode,
	},
	"RevokeNode": {
		strings.ToUpper("Delete"),
		"/rks/v1/group/{groupname:[a-zA-Z0-9\\-]{1,64}}/nodes/{nodeId}",
		false,
		admin.RevokeNode,
	},
}

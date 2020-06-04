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
package utils

import (
	"bytes"
	"encoding/json"
	"net/http"
	"text/template"

	"github.com/Orange-OpenSource/remote-key-server/pkg/model"
)

// DecodeHTTPJSONBodyToStruct Decodes given request body inside given struct
// Given struct must be passed as a pointer
func DecodeHTTPJSONBodyToStruct(r *http.Request, s interface{}) *model.RksError {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(s); err != nil {
		return &model.RksError{WrappedError: err, Message: "failed to decode json request body", Code: 400}
	}
	return nil
}

// WriteStructAsJson writes the given interface converted to json into the given ResponseWriter
// If w.WriteHeader has not been called yet, Write calls WriteHeader(http.StatusOK) before writing the data
// If a StatusOk is not wanted it is mandatory to set the status code before calling this function
func WriteStructAsJSON(w http.ResponseWriter, s interface{}) *model.RksError {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err := json.NewEncoder(w).Encode(&s); err != nil {
		return &model.RksError{WrappedError: err, Message: "failed to encode struct to json", Code: 500}
	}
	return nil
}

func UpdateTemplatedPolicy(policyTpl string, s interface{}) (string, error) {
	tpl, err := template.New("GroupSecretAccessPolicy").Parse(policyTpl)
	if err != nil {
		return "", err
	}

	policy := new(bytes.Buffer)

	err = tpl.Execute(policy, s)
	if err != nil {
		return "", err
	}
	return policy.String(), nil
}

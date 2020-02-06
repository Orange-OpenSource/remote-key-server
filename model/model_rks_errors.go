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
package model

import (
	"fmt"
	//"log"
	"context"
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/Orange-OpenSource/remote-key-server/logger"
)

type RksError struct {
	WrappedError error
	Message      string
	Code         int
}

func (err RksError) Error() string {
	if err.WrappedError != nil {
		return fmt.Sprintf("%v - Wrapped Error: %v Returned Code: %v", err.Message, err.WrappedError, err.Code)
	}
	return fmt.Sprintf("%v - Returned Code: %v", err.Message, err.Code)
}

func (err RksError) HandleErr(ctx context.Context, w http.ResponseWriter) {
	l := logger.NewLoggerFromContext(ctx)
	l.WithFields(log.Fields{"wrapped_err": err.WrappedError, "status": err.Code}).Error(err.Message)
	http.Error(w, err.Message, err.Code)
}

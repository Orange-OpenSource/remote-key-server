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
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/Orange-OpenSource/remote-key-server/pkg/api"
	"github.com/Orange-OpenSource/remote-key-server/pkg/api/admin"
	"github.com/Orange-OpenSource/remote-key-server/pkg/healthcheck"
	"github.com/Orange-OpenSource/remote-key-server/pkg/logger"
	"github.com/Orange-OpenSource/remote-key-server/pkg/model"
	"github.com/Orange-OpenSource/remote-key-server/pkg/vault"
)

func init() {
	flag.StringVar(&vault.Config.VaultAddr, "vaultaddr", "http://localhost:8200", "Vault address")
	flag.StringVar(&vault.Config.Certificate, "cert", "./certs/rks.local.pem", "Certificate")
	flag.StringVar(&vault.Config.PrivateKey, "pkey", "./certs/rks.local.key", "Private Key")
	flag.StringVar(&vault.Config.ListenAddress, "listenAddress", ":8080", "Listen Address of form: {ip}:{port}")
	flag.StringVar(&vault.Config.AdminLogin, "adminLogin", "", "Admin Login (required)")
	flag.StringVar(&vault.Config.AdminPwd, "adminPwd", "", "Admin Password (required)")
}

func main() {
	var ok bool

	logrus.Info("Server starting")
	logrus.SetLevel(logrus.DebugLevel)

	flag.Parse()

	config := vault.Config
	if config.VaultAddr == "" {
		if config.VaultAddr, ok = os.LookupEnv("VAULT_ADDR"); !ok {
			flag.Usage()
			os.Exit(1)
		}
	}

	if config.AdminLogin == "" {
		flag.Usage()
		logrus.Fatal("AdminLogin is required")
	}

	if config.AdminPwd == "" {
		flag.Usage()
		logrus.Fatal("AdminPwd is required")
	}

	router := mux.NewRouter()
	router.StrictSlash(true)

	// Create global logger which will be derived
	baseLogger := logrus.New()
	baseLogger.SetLevel(logrus.DebugLevel)
	logger.SetBaseLogger(baseLogger)

	loggingMiddleware := logger.LoggingMiddleware{}
	router.Use(loggingMiddleware.Middleware)

	router.NotFoundHandler = logger.NotFoundLogger()
	router.MethodNotAllowedHandler = logger.MethodNotAllowedLogger()

	api.NewApiRouter(router)
	router.Handle("/metrics", promhttp.Handler())
	router.Handle("/healthz", healthcheck.Healthcheck(&config))

	router.Use(api.ContentEncodingCheckerMiddleWare)
	router.Use(api.ContentTypeCheckerMiddleWare)

	instrumentedRouter := model.MetricsHandler(router)

	logrus.WithField("config", fmt.Sprintf("%+v", config)).Debug("config")

	go admin.PeriodicGroupTokensRenew()

	var srv http.Server
	srv.Addr = config.ListenAddress
	srv.Handler = instrumentedRouter

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
		<-sigint

		// We received an interrupt signal, shut down.
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			logrus.WithFields(logrus.Fields{"error": err}).Fatal("HTTP server Shutdown")
		}
		close(idleConnsClosed)
	}()

	if err := srv.ListenAndServeTLS(config.Certificate, config.PrivateKey); err != http.ErrServerClosed {
		// Error starting or closing listener:
		logrus.WithFields(logrus.Fields{"error": err}).Fatal("HTTP server ListenAndServe")
	}

	<-idleConnsClosed
}

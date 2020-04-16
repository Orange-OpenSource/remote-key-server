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
package logger

import (
	"context"
	"net"
	"net/http"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// contextCorrelationID is a type used to reference values stored in a context
type contextCorrelationID int

const (
	loggerKeyID contextCorrelationID = iota // loggerKeyID is the key to recover a logger stored in a context
)

// LoggingMiddleware is a Gorilla Mux middleware that logs information using logrus
type LoggingMiddleware struct {
	baseLogger logrus.FieldLogger
}

var Logger LoggingMiddleware

// DefaultLogger returns logging middleware base logger
func GetBaseLogger() logrus.FieldLogger {
	return Logger.baseLogger
}

func SetBaseLogger(l logrus.FieldLogger) {
	Logger.baseLogger = l
}

// NewLoggerFromContext returns a logrus logger
// The logger is recovered from the given context or the StandardLogger
func NewLoggerFromContext(ctx context.Context) logrus.FieldLogger {
	if ctx != nil {
		if embeddedLogger, ok := ctx.Value(loggerKeyID).(logrus.FieldLogger); ok {
			return embeddedLogger
		}
	}
	return Logger.baseLogger
}

// ContextWithLogger returns a context with a logrus logger embedded as a Value
func ContextWithLogger(ctx context.Context, entry logrus.FieldLogger) context.Context {
	return context.WithValue(ctx, loggerKeyID, entry)
}

// responseWriter wraps the http.ResponseWriter in order to get http status and body return size
type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func newResponseWriter(rw http.ResponseWriter) *responseWriter {
	nrw := &responseWriter{
		ResponseWriter: rw,
	}
	return nrw
}

// WriteHeader is wrapped to get the status
func (rw *responseWriter) WriteHeader(s int) {
	rw.status = s
	rw.ResponseWriter.WriteHeader(s)
}

// Write is wrapped to get body size
func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.Written() {
		// The status will be StatusOK if WriteHeader has not been called yet
		rw.WriteHeader(http.StatusOK)
	}
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

func (rw *responseWriter) Written() bool {
	return rw.status != 0
}

// WithRequestStatus returns a new logger with fields: returned HTTP Status and HTTP body size
// The fields are extracted from our custom responseWriter type
func WithResponseStatus(logger logrus.FieldLogger, rw http.ResponseWriter) logrus.FieldLogger {
	if customResponseWriter, ok := rw.(*responseWriter); ok {
		return logger.WithFields(logrus.Fields{"status": customResponseWriter.status, "body_size": customResponseWriter.size})
	}
	return logger
}

// Middleware implement Gorilla Mux middleware interface
// The function is called for every request
// It builds a customized logger for the request and pass it in the request context for use in the endpoint
func (l LoggingMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loggedResponseWriter := newResponseWriter(w)

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}

		// Generate request ID
		// TODO: Check request header if request ID already present
		reqID, err := uuid.NewUUID()
		if err != nil {
			logrus.Error("failed uuid generation")
		}

		requestLogger := Logger.baseLogger.WithFields(logrus.Fields{"method": r.Method, "url": r.RequestURI, "client_ip": host, "request_id": reqID.String()})

		if l, ok := Logger.baseLogger.(*logrus.Logger); ok && l.Level == logrus.DebugLevel {
			if h := r.Header.Get("X-Vault-Token"); h != "" {
				requestLogger = requestLogger.WithField("X-Vault-Token", h)
			}
		}

		// Create a new context from the request and add the requestLogger to it
		w.Header().Add("Request-ID", reqID.String())
		ctxWithLogger := ContextWithLogger(r.Context(), requestLogger)

		// Execute next handler by passing the custom responseWriter and the request with our customized logger
		r = r.WithContext(ctxWithLogger)
		next.ServeHTTP(loggedResponseWriter, r)

		// Logging here won't include fields added
		// Log if status is not an error. Errors are logged by the error handler
	})
}

func NotFoundLogger() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}

		Logger.baseLogger.WithFields(logrus.Fields{"method": r.Method, "url": r.RequestURI, "client_ip": host, "headers": r.Header}).Info("no route found")

		http.Error(w, "No Route", 404)
	}
}

func MethodNotAllowedLogger() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}

		Logger.baseLogger.WithFields(logrus.Fields{"method": r.Method, "url": r.RequestURI, "client_ip": host, "headers": r.Header}).Info("no method found")

		// Was 405 Method Not Allowed but send 404 for coherence
		http.Error(w, "No Route", 404)
	}
}

// Package httpx has small HTTP helpers shared by every service: JSON encoding,
// the error envelope (CTL-040), request limits and security headers.
package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mcp-gateway/mcp-gateway/internal/ports"
)

// MaxBody is the default request body limit.
const MaxBody = 1 << 20

// ErrorBody is the JSON error envelope.
type ErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// WriteJSON writes v as JSON with status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// StatusFor maps service errors to HTTP status and code.
func StatusFor(err error) (int, string) {
	switch {
	case errors.Is(err, ports.ErrInvalid):
		return http.StatusBadRequest, "invalid_request"
	case errors.Is(err, ports.ErrUnauthenticated):
		return http.StatusUnauthorized, "unauthenticated"
	case errors.Is(err, ports.ErrForbidden):
		return http.StatusForbidden, "forbidden"
	case errors.Is(err, ports.ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, ports.ErrConflict):
		return http.StatusConflict, "conflict"
	case errors.Is(err, ports.ErrNoCredential):
		return http.StatusFailedDependency, "no_credential"
	case errors.Is(err, ports.ErrNeedsReauth):
		return http.StatusFailedDependency, "needs_reauth"
	}
	return http.StatusInternalServerError, "internal"
}

// WriteError writes the error envelope. Internal errors are logged and replaced by a
// generic message so stack traces and internals never reach clients (UI-015).
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	status, code := StatusFor(err)
	msg := err.Error()
	if status == http.StatusInternalServerError {
		slog.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		msg = "something went wrong on the gateway; check its logs"
	}
	var b ErrorBody
	b.Error.Code, b.Error.Message = code, msg
	WriteJSON(w, status, b)
}

// WriteErr writes an error envelope with an explicit status and code.
func WriteErr(w http.ResponseWriter, status int, code, msg string) {
	var b ErrorBody
	b.Error.Code, b.Error.Message = code, msg
	WriteJSON(w, status, b)
}

// DecodeJSON decodes a JSON body with a size limit and unknown-field rejection.
func DecodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: invalid JSON body: %v", ports.ErrInvalid, err)
	}
	return nil
}

// ReadBody reads a limited body.
func ReadBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ports.ErrInvalid, err)
	}
	return b, nil
}

// Bearer extracts a bearer token from the Authorization header.
func Bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// SecurityHeaders adds conservative security headers to every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

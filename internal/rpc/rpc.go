// Package rpc carries the ports interfaces over internal HTTP for microservices
// mode (DEP-001, DEP-002). Each call is POST /internal/v1/<service>/<method> with a
// JSON body, authenticated with the shared internal token.
package rpc

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mcp-gateway/mcp-gateway/internal/httpx"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
)

// Prefix is where internal routes are mounted.
const Prefix = "/internal/v1/"

// Server dispatches internal calls.
type Server struct {
	token string
	mux   *http.ServeMux
}

// NewServer returns a Server that requires token on every call.
func NewServer(token string) *Server { return &Server{token: token, mux: http.NewServeMux()} }

// ServeHTTP authenticates and dispatches.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	got := httpx.Bearer(r)
	if s.token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
		httpx.WriteErr(w, http.StatusUnauthorized, "unauthenticated", "internal token required")
		return
	}
	s.mux.ServeHTTP(w, r)
}

type envelope struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Handle registers fn as service/method.
func Handle[Req, Resp any](s *Server, name string, fn func(ctx context.Context, req Req) (Resp, error)) {
	s.mux.HandleFunc("POST "+Prefix+name, func(w http.ResponseWriter, r *http.Request) {
		var req Req
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
		if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			httpx.WriteErr(w, 400, "invalid_request", "bad internal request: "+err.Error())
			return
		}
		resp, err := fn(r.Context(), req)
		if err != nil {
			status, code := httpx.StatusFor(err)
			httpx.WriteErr(w, status, code, err.Error())
			return
		}
		b, err := json.Marshal(resp)
		if err != nil {
			httpx.WriteErr(w, 500, "internal", err.Error())
			return
		}
		httpx.WriteJSON(w, 200, envelope{Result: b})
	})
}

// Client calls a remote service.
type Client struct {
	base  string
	token string
	hc    *http.Client
}

// NewClient returns a client for the service at baseURL.
func NewClient(baseURL, token string) *Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 64
	return &Client{base: strings.TrimRight(baseURL, "/"), token: token, hc: &http.Client{Transport: t}}
}

var codeErrors = map[string]error{
	"invalid_request": ports.ErrInvalid, "unauthenticated": ports.ErrUnauthenticated, "forbidden": ports.ErrForbidden,
	"not_found": ports.ErrNotFound, "conflict": ports.ErrConflict, "no_credential": ports.ErrNoCredential, "needs_reauth": ports.ErrNeedsReauth,
}

// remoteError keeps the remote message while matching the sentinel with errors.Is.
type remoteError struct {
	sentinel error
	msg      string
}

func (e *remoteError) Error() string { return e.msg }
func (e *remoteError) Unwrap() error { return e.sentinel }

// Call invokes service/method. A zero timeout means the context decides.
func Call[Req, Resp any](ctx context.Context, c *Client, name string, req Req) (Resp, error) {
	var zero Resp
	body, err := json.Marshal(req)
	if err != nil {
		return zero, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+Prefix+name, bytes.NewReader(body))
	if err != nil {
		return zero, err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.hc.Do(hr)
	if err != nil {
		return zero, fmt.Errorf("internal call %s: %w", name, err)
	}
	defer resp.Body.Close()
	var env envelope
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&env); err != nil {
		return zero, fmt.Errorf("internal call %s: HTTP %d: undecodable response", name, resp.StatusCode)
	}
	if env.Error != nil {
		if s, ok := codeErrors[env.Error.Code]; ok {
			return zero, &remoteError{sentinel: s, msg: env.Error.Message}
		}
		return zero, fmt.Errorf("internal call %s: %s", name, env.Error.Message)
	}
	if err := json.Unmarshal(env.Result, &zero); err != nil {
		return zero, err
	}
	return zero, nil
}

// Ping checks that the remote service is alive (its /healthz). It deliberately does
// not use /readyz: services depend on each other and readiness would recurse.
func (c *Client) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/healthz", nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s not ready (HTTP %d)", c.base, resp.StatusCode)
	}
	return nil
}

// Empty is used for calls without arguments or results.
type Empty struct{}

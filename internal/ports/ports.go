// Package ports defines the interfaces between services.
//
// The gateway (data plane) depends only on these interfaces. In single-binary
// mode they are satisfied by the services directly (in-process calls); in
// microservices mode by the HTTP clients in internal/rpc. Adding a new adapter
// (gRPC, NATS, …) means implementing these interfaces, nothing else.
package ports

import (
	"context"
	"errors"
	"time"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
)

// Errors shared across service boundaries. RPC adapters map them to and from HTTP codes.
var (
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrForbidden       = errors.New("forbidden")
	ErrNotFound        = errors.New("not found")
	ErrConflict        = errors.New("conflict")
	ErrInvalid         = errors.New("invalid request")
	ErrNoCredential    = errors.New("no credential configured for this server")
	ErrNeedsReauth     = errors.New("server connection expired; reconnect it in the dashboard")
)

// Authenticator resolves a bearer token (static gw_ token or JWT) to an Identity.
type Authenticator interface {
	Authenticate(ctx context.Context, bearer string) (domain.Identity, error)
}

// ConfigSource supplies the versioned configuration snapshot.
type ConfigSource interface {
	// Snapshot returns the current snapshot. If since >= 0, it waits (up to the
	// context deadline or ~25 s) until the version is greater than since.
	Snapshot(ctx context.Context, since int64) (domain.Snapshot, error)
}

// Credential kinds.
const (
	CredBearer = "bearer"
	CredHeader = "header"
	CredEnv    = "env"
	CredOAuth  = "oauth"
)

// Credential is a decrypted upstream credential, ready to inject.
type Credential struct {
	Kind        string            `json:"kind"`
	Token       string            `json:"token,omitempty"`        // bearer, oauth (access token)
	HeaderName  string            `json:"header_name,omitempty"`  // header
	HeaderValue string            `json:"header_value,omitempty"` // header
	Env         map[string]string `json:"env,omitempty"`          // env
	ExpiresAt   time.Time         `json:"expires_at,omitempty"`
}

// Secrets lists the secret values in the credential, for redaction.
func (c Credential) Secrets() []string {
	var out []string
	for _, s := range []string{c.Token, c.HeaderValue} {
		if len(s) >= 6 {
			out = append(out, s)
		}
	}
	for _, v := range c.Env {
		if len(v) >= 6 {
			out = append(out, v)
		}
	}
	return out
}

// CredentialProvider gives the gateway upstream credentials.
type CredentialProvider interface {
	GetCredential(ctx context.Context, userID, serverID string) (Credential, error)
	// ForceRefresh is called after an upstream 401. It refreshes OAuth tokens or,
	// if that is impossible, marks the credential as needing re-authentication.
	ForceRefresh(ctx context.Context, userID, serverID string) (Credential, error)
	// MarkNeedsReauth flags the credential after the upstream rejected it again (GW-009).
	MarkNeedsReauth(ctx context.Context, userID, serverID string) error
}

// AuditSink records audit events. Implementations must be safe for concurrent use.
type AuditSink interface {
	Record(ctx context.Context, events []domain.AuditEvent) error
}

// ApprovalBroker turns an "ask" decision into a human decision.
type ApprovalBroker interface {
	// RequestApproval creates a pending approval and blocks until it is decided or expires.
	RequestApproval(ctx context.Context, a domain.Approval) (domain.Approval, error)
}

// ToolDef is the part of an upstream tool definition that is fingerprinted.
type ToolDef struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"input_schema,omitempty"`
	Annotations any    `json:"annotations,omitempty"`
}

// PinRegistry decides whether upstream tools are trusted (tool pinning).
type PinRegistry interface {
	// ObserveTools reports the tools a server currently advertises and returns
	// the resulting pins (approved or quarantined) for them.
	ObserveTools(ctx context.Context, serverID string, tools []ToolDef) ([]domain.ToolPin, error)
}

package rpc

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/mcp-gateway/mcp-gateway/internal/adminapi"
	"github.com/mcp-gateway/mcp-gateway/internal/domain"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
	"github.com/mcp-gateway/mcp-gateway/internal/services/auth"
	"github.com/mcp-gateway/mcp-gateway/internal/services/vault"
)

// ---- request/response shapes ----

type (
	tokReq       struct{ Token string }
	adminAuthReq struct{ SessionID, Bearer string }
	userIDReq    struct{ UserID string }
	setRoleReq   struct {
		UserID string
		Role   domain.Role
	}
	inviteReq struct {
		By   string
		Role domain.Role
	}
	keyReq  struct{ UserID, Name string }
	keyResp struct {
		Key  string
		Meta auth.AdminKey
	}
	idReq         struct{ ID string }
	staticTokReq  struct{ UserID, Name, Profile string }
	staticTokResp struct {
		Token  string
		Client domain.Client
	}
	profileReq struct{ ID, Profile string }
	credReq    struct{ UserID, ServerID string }
	setCredReq struct {
		UserID, ServerID string
		Cred             ports.Credential
	}
	serverReq  struct{ ServerID string }
	connectReq struct{ State, Code string }
	sinceReq   struct{ Since int64 }
	observeReq struct {
		ServerID string
		Tools    []ports.ToolDef
	}
	probeReq struct{ ServerID, UserID string }
)

// ---- auth ----

// AuthService is the server-side auth surface.
type AuthService interface {
	ports.Authenticator
	adminapi.Auth
}

// RegisterAuth exposes an auth service.
func RegisterAuth(s *Server, a AuthService) {
	Handle(s, "auth/Authenticate", func(ctx context.Context, r tokReq) (domain.Identity, error) { return a.Authenticate(ctx, r.Token) })
	Handle(s, "auth/AuthenticateAdmin", func(ctx context.Context, r adminAuthReq) (auth.Principal, error) {
		return a.AuthenticateAdmin(ctx, r.SessionID, r.Bearer)
	})
	Handle(s, "auth/ListUsers", func(ctx context.Context, _ Empty) ([]domain.User, error) { return a.ListUsers(ctx) })
	Handle(s, "auth/SetRole", func(ctx context.Context, r setRoleReq) (Empty, error) {
		return Empty{}, a.SetRole(ctx, r.UserID, r.Role)
	})
	Handle(s, "auth/DeleteUser", func(ctx context.Context, r userIDReq) (Empty, error) { return Empty{}, a.DeleteUser(ctx, r.UserID) })
	Handle(s, "auth/CreateInvite", func(ctx context.Context, r inviteReq) (string, error) { return a.CreateInvite(ctx, r.By, r.Role) })
	Handle(s, "auth/CreateAdminKey", func(ctx context.Context, r keyReq) (keyResp, error) {
		k, m, err := a.CreateAdminKey(ctx, r.UserID, r.Name)
		return keyResp{k, m}, err
	})
	Handle(s, "auth/ListAdminKeys", func(ctx context.Context, _ Empty) ([]auth.AdminKey, error) { return a.ListAdminKeys(ctx) })
	Handle(s, "auth/RevokeAdminKey", func(ctx context.Context, r idReq) (Empty, error) { return Empty{}, a.RevokeAdminKey(ctx, r.ID) })
	Handle(s, "auth/ListClients", func(ctx context.Context, r userIDReq) ([]domain.Client, error) { return a.ListClients(ctx, r.UserID) })
	Handle(s, "auth/GetClient", func(ctx context.Context, r idReq) (domain.Client, error) { return a.GetClient(ctx, r.ID) })
	Handle(s, "auth/CreateStaticToken", func(ctx context.Context, r staticTokReq) (staticTokResp, error) {
		t, c, err := a.CreateStaticToken(ctx, r.UserID, r.Name, r.Profile)
		return staticTokResp{t, c}, err
	})
	Handle(s, "auth/RevokeClient", func(ctx context.Context, r idReq) (Empty, error) { return Empty{}, a.RevokeClient(ctx, r.ID) })
	Handle(s, "auth/SetClientProfile", func(ctx context.Context, r profileReq) (Empty, error) {
		return Empty{}, a.SetClientProfile(ctx, r.ID, r.Profile)
	})
	Handle(s, "auth/SigningKey", func(ctx context.Context, _ Empty) (auth.SigningKeyInfo, error) { return a.SigningKey(), nil })
	Handle(s, "auth/RotateSigningKey", func(ctx context.Context, _ Empty) (Empty, error) { return Empty{}, a.RotateSigningKey(ctx) })
}

// AuthClient implements AuthService remotely, with a short identity cache on the hot path.
type AuthClient struct {
	C  *Client
	mu sync.Mutex
	ic map[[32]byte]idCache
}

type idCache struct {
	id    domain.Identity
	until time.Time
}

func (a *AuthClient) Authenticate(ctx context.Context, tok string) (domain.Identity, error) {
	k := sha256.Sum256([]byte(tok))
	a.mu.Lock()
	if a.ic == nil {
		a.ic = map[[32]byte]idCache{}
	}
	e, ok := a.ic[k]
	a.mu.Unlock()
	if ok && time.Now().Before(e.until) {
		return e.id, nil
	}
	id, err := Call[tokReq, domain.Identity](ctx, a.C, "auth/Authenticate", tokReq{tok})
	if err == nil {
		a.mu.Lock()
		if len(a.ic) > 10000 {
			a.ic = map[[32]byte]idCache{}
		}
		a.ic[k] = idCache{id, time.Now().Add(30 * time.Second)}
		a.mu.Unlock()
	}
	return id, err
}
func (a *AuthClient) AuthenticateAdmin(ctx context.Context, sid, bearer string) (auth.Principal, error) {
	return Call[adminAuthReq, auth.Principal](ctx, a.C, "auth/AuthenticateAdmin", adminAuthReq{sid, bearer})
}
func (a *AuthClient) ListUsers(ctx context.Context) ([]domain.User, error) {
	return Call[Empty, []domain.User](ctx, a.C, "auth/ListUsers", Empty{})
}
func (a *AuthClient) SetRole(ctx context.Context, u string, r domain.Role) error {
	_, err := Call[setRoleReq, Empty](ctx, a.C, "auth/SetRole", setRoleReq{u, r})
	return err
}
func (a *AuthClient) DeleteUser(ctx context.Context, u string) error {
	_, err := Call[userIDReq, Empty](ctx, a.C, "auth/DeleteUser", userIDReq{u})
	return err
}
func (a *AuthClient) CreateInvite(ctx context.Context, by string, r domain.Role) (string, error) {
	return Call[inviteReq, string](ctx, a.C, "auth/CreateInvite", inviteReq{by, r})
}
func (a *AuthClient) CreateAdminKey(ctx context.Context, u, n string) (string, auth.AdminKey, error) {
	r, err := Call[keyReq, keyResp](ctx, a.C, "auth/CreateAdminKey", keyReq{u, n})
	return r.Key, r.Meta, err
}
func (a *AuthClient) ListAdminKeys(ctx context.Context) ([]auth.AdminKey, error) {
	return Call[Empty, []auth.AdminKey](ctx, a.C, "auth/ListAdminKeys", Empty{})
}
func (a *AuthClient) RevokeAdminKey(ctx context.Context, id string) error {
	_, err := Call[idReq, Empty](ctx, a.C, "auth/RevokeAdminKey", idReq{id})
	return err
}
func (a *AuthClient) ListClients(ctx context.Context, u string) ([]domain.Client, error) {
	return Call[userIDReq, []domain.Client](ctx, a.C, "auth/ListClients", userIDReq{u})
}
func (a *AuthClient) GetClient(ctx context.Context, id string) (domain.Client, error) {
	return Call[idReq, domain.Client](ctx, a.C, "auth/GetClient", idReq{id})
}
func (a *AuthClient) CreateStaticToken(ctx context.Context, u, n, p string) (string, domain.Client, error) {
	r, err := Call[staticTokReq, staticTokResp](ctx, a.C, "auth/CreateStaticToken", staticTokReq{u, n, p})
	return r.Token, r.Client, err
}
func (a *AuthClient) RevokeClient(ctx context.Context, id string) error {
	_, err := Call[idReq, Empty](ctx, a.C, "auth/RevokeClient", idReq{id})
	a.mu.Lock()
	a.ic = nil // drop cached identities so revocation applies at once on this replica
	a.mu.Unlock()
	return err
}
func (a *AuthClient) SetClientProfile(ctx context.Context, id, p string) error {
	_, err := Call[profileReq, Empty](ctx, a.C, "auth/SetClientProfile", profileReq{id, p})
	return err
}
func (a *AuthClient) SigningKey() auth.SigningKeyInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	k, _ := Call[Empty, auth.SigningKeyInfo](ctx, a.C, "auth/SigningKey", Empty{})
	return k
}
func (a *AuthClient) RotateSigningKey(ctx context.Context) error {
	_, err := Call[Empty, Empty](ctx, a.C, "auth/RotateSigningKey", Empty{})
	return err
}

// ---- vault ----

// VaultService is the server-side vault surface.
type VaultService interface {
	ports.CredentialProvider
	adminapi.Vault
}

// RegisterVault exposes a vault.
func RegisterVault(s *Server, v VaultService) {
	Handle(s, "vault/GetCredential", func(ctx context.Context, r credReq) (ports.Credential, error) {
		return v.GetCredential(ctx, r.UserID, r.ServerID)
	})
	Handle(s, "vault/ForceRefresh", func(ctx context.Context, r credReq) (ports.Credential, error) {
		return v.ForceRefresh(ctx, r.UserID, r.ServerID)
	})
	Handle(s, "vault/MarkNeedsReauth", func(ctx context.Context, r credReq) (Empty, error) {
		return Empty{}, v.MarkNeedsReauth(ctx, r.UserID, r.ServerID)
	})
	Handle(s, "vault/SetCredential", func(ctx context.Context, r setCredReq) (Empty, error) {
		return Empty{}, v.SetCredential(ctx, r.UserID, r.ServerID, r.Cred)
	})
	Handle(s, "vault/DeleteCredential", func(ctx context.Context, r credReq) (Empty, error) {
		return Empty{}, v.DeleteCredential(ctx, r.UserID, r.ServerID)
	})
	Handle(s, "vault/ListCredentials", func(ctx context.Context, r serverReq) ([]vault.CredentialInfo, error) {
		return v.ListCredentials(ctx, r.ServerID)
	})
	Handle(s, "vault/DeleteServer", func(ctx context.Context, r serverReq) (Empty, error) { return Empty{}, v.DeleteServer(ctx, r.ServerID) })
	Handle(s, "vault/SetOAuthApp", func(ctx context.Context, r vault.OAuthApp) (Empty, error) { return Empty{}, v.SetOAuthApp(ctx, r) })
	Handle(s, "vault/StartConnect", func(ctx context.Context, r credReq) (string, error) { return v.StartConnect(ctx, r.UserID, r.ServerID) })
	Handle(s, "vault/CompleteConnect", func(ctx context.Context, r connectReq) (string, error) {
		return v.CompleteConnect(ctx, r.State, r.Code)
	})
	Handle(s, "vault/KeyProvider", func(ctx context.Context, _ Empty) (adminapi.KeyProviderInfo, error) { return v.KeyProvider(), nil })
}

// VaultClient implements VaultService remotely.
type VaultClient struct{ C *Client }

func (v VaultClient) GetCredential(ctx context.Context, u, s string) (ports.Credential, error) {
	return Call[credReq, ports.Credential](ctx, v.C, "vault/GetCredential", credReq{u, s})
}
func (v VaultClient) ForceRefresh(ctx context.Context, u, s string) (ports.Credential, error) {
	return Call[credReq, ports.Credential](ctx, v.C, "vault/ForceRefresh", credReq{u, s})
}
func (v VaultClient) MarkNeedsReauth(ctx context.Context, u, s string) error {
	_, err := Call[credReq, Empty](ctx, v.C, "vault/MarkNeedsReauth", credReq{u, s})
	return err
}
func (v VaultClient) SetCredential(ctx context.Context, u, s string, c ports.Credential) error {
	_, err := Call[setCredReq, Empty](ctx, v.C, "vault/SetCredential", setCredReq{u, s, c})
	return err
}
func (v VaultClient) DeleteCredential(ctx context.Context, u, s string) error {
	_, err := Call[credReq, Empty](ctx, v.C, "vault/DeleteCredential", credReq{u, s})
	return err
}
func (v VaultClient) ListCredentials(ctx context.Context, s string) ([]vault.CredentialInfo, error) {
	return Call[serverReq, []vault.CredentialInfo](ctx, v.C, "vault/ListCredentials", serverReq{s})
}
func (v VaultClient) DeleteServer(ctx context.Context, s string) error {
	_, err := Call[serverReq, Empty](ctx, v.C, "vault/DeleteServer", serverReq{s})
	return err
}
func (v VaultClient) SetOAuthApp(ctx context.Context, a vault.OAuthApp) error {
	_, err := Call[vault.OAuthApp, Empty](ctx, v.C, "vault/SetOAuthApp", a)
	return err
}
func (v VaultClient) StartConnect(ctx context.Context, u, s string) (string, error) {
	return Call[credReq, string](ctx, v.C, "vault/StartConnect", credReq{u, s})
}
func (v VaultClient) CompleteConnect(ctx context.Context, st, code string) (string, error) {
	return Call[connectReq, string](ctx, v.C, "vault/CompleteConnect", connectReq{st, code})
}
func (v VaultClient) KeyProvider() adminapi.KeyProviderInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	k, _ := Call[Empty, adminapi.KeyProviderInfo](ctx, v.C, "vault/KeyProvider", Empty{})
	return k
}

// ---- control (the gateway's view) ----

// ControlPorts is what the gateway needs from control.
type ControlPorts interface {
	ports.ConfigSource
	ports.AuditSink
	ports.ApprovalBroker
	ports.PinRegistry
}

// ControlService is the server-side control surface.
type ControlService interface {
	ControlPorts
	ListProfiles(ctx context.Context) ([]domain.Profile, error)
}

// RegisterControl exposes control.
func RegisterControl(s *Server, c ControlService) {
	Handle(s, "control/Snapshot", func(ctx context.Context, r sinceReq) (domain.Snapshot, error) { return c.Snapshot(ctx, r.Since) })
	Handle(s, "control/Record", func(ctx context.Context, evs []domain.AuditEvent) (Empty, error) { return Empty{}, c.Record(ctx, evs) })
	Handle(s, "control/RequestApproval", func(ctx context.Context, a domain.Approval) (domain.Approval, error) {
		return c.RequestApproval(ctx, a)
	})
	Handle(s, "control/ObserveTools", func(ctx context.Context, r observeReq) ([]domain.ToolPin, error) {
		return c.ObserveTools(ctx, r.ServerID, r.Tools)
	})
	Handle(s, "control/ProfileNames", func(ctx context.Context, _ Empty) ([]string, error) {
		ps, err := c.ListProfiles(ctx)
		names := make([]string, 0, len(ps))
		for _, p := range ps {
			names = append(names, p.Name)
		}
		return names, err
	})
}

// ControlClient implements the gateway-facing control ports remotely.
type ControlClient struct{ C *Client }

func (c ControlClient) Snapshot(ctx context.Context, since int64) (domain.Snapshot, error) {
	return Call[sinceReq, domain.Snapshot](ctx, c.C, "control/Snapshot", sinceReq{since})
}
func (c ControlClient) Record(ctx context.Context, evs []domain.AuditEvent) error {
	_, err := Call[[]domain.AuditEvent, Empty](ctx, c.C, "control/Record", evs)
	return err
}
func (c ControlClient) RequestApproval(ctx context.Context, a domain.Approval) (domain.Approval, error) {
	return Call[domain.Approval, domain.Approval](ctx, c.C, "control/RequestApproval", a)
}
func (c ControlClient) ObserveTools(ctx context.Context, server string, tools []ports.ToolDef) ([]domain.ToolPin, error) {
	return Call[observeReq, []domain.ToolPin](ctx, c.C, "control/ObserveTools", observeReq{server, tools})
}

// ProfileNames lists profile names (for the OAuth consent screen).
func (c ControlClient) ProfileNames(ctx context.Context) ([]string, error) {
	return Call[Empty, []string](ctx, c.C, "control/ProfileNames", Empty{})
}

// ---- gateway probe ----

// RegisterProber exposes the gateway's Probe.
func RegisterProber(s *Server, p adminapi.Prober) {
	Handle(s, "gateway/Probe", func(ctx context.Context, r probeReq) (int, error) { return p.Probe(ctx, r.ServerID, r.UserID) })
}

// ProberClient implements adminapi.Prober remotely.
type ProberClient struct{ C *Client }

func (p ProberClient) Probe(ctx context.Context, server, user string) (int, error) {
	return Call[probeReq, int](ctx, p.C, "gateway/Probe", probeReq{server, user})
}

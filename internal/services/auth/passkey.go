package auth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
)

const ceremonyTTL = 5 * time.Minute

// Registration purposes.
const (
	RegisterSetup  = "setup"  // first owner, with the setup token (AUTH-030)
	RegisterInvite = "invite" // new user, with an invite token
	RegisterAdd    = "add"    // existing logged-in user adds another passkey
)

type regMeta struct {
	Purpose string      `json:"purpose"`
	Token   string      `json:"token,omitempty"`
	Name    string      `json:"name"`
	UserID  string      `json:"user_id,omitempty"`
	Handle  []byte      `json:"handle"`
	Role    domain.Role `json:"role,omitempty"`
}

func (s *Service) saveCeremony(ctx context.Context, kind, userID string, sd *webauthn.SessionData, meta any) (string, error) {
	id := randomToken(18)
	data, _ := json.Marshal(sd)
	m, _ := json.Marshal(meta)
	_, err := s.db.ExecContext(ctx, `INSERT INTO ceremonies(id, kind, user_id, data, meta, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, kind, userID, string(data), string(m), s.now().Add(ceremonyTTL).Unix())
	_, _ = s.db.ExecContext(ctx, `DELETE FROM ceremonies WHERE expires_at < ?`, s.now().Unix())
	return id, err
}

// takeCeremony loads and deletes a ceremony (challenges are single-use, AUTH-031).
func (s *Service) takeCeremony(ctx context.Context, id, kind string) (webauthn.SessionData, []byte, error) {
	var data, meta string
	var exp int64
	err := s.db.QueryRowContext(ctx, `DELETE FROM ceremonies WHERE id=? AND kind=? RETURNING data, meta, expires_at`, id, kind).Scan(&data, &meta, &exp)
	if err != nil || s.now().Unix() > exp {
		return webauthn.SessionData{}, nil, fmt.Errorf("%w: passkey challenge expired or already used; try again", ports.ErrForbidden)
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal([]byte(data), &sd); err != nil {
		return sd, nil, err
	}
	return sd, []byte(meta), nil
}

func (s *Service) loadWAUser(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, where string, arg any) (*waUser, error) {
	u := &waUser{}
	var created int64
	err := q.QueryRowContext(ctx, `SELECT id, name, role, webauthn_id, created_at FROM users WHERE `+where, arg).Scan(&u.ID, &u.Name, &u.Role, &u.handle, &created)
	if err != nil {
		return nil, err
	}
	u.CreatedAt = time.Unix(created, 0).UTC()
	rows, err := q.QueryContext(ctx, `SELECT data FROM passkeys WHERE user_id=?`, u.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(d), &c); err != nil {
			return nil, err
		}
		u.creds = append(u.creds, c)
	}
	return u, rows.Err()
}

// BeginRegistration starts a passkey registration. For setup and invite, token is
// required and checked now (and consumed at finish); for add, userID is required.
func (s *Service) BeginRegistration(ctx context.Context, purpose, token, name, userID string) (string, *protocol.CredentialCreation, error) {
	meta := regMeta{Purpose: purpose, Token: token, Name: name}
	var user *waUser
	switch purpose {
	case RegisterSetup:
		var ok int
		s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM setup WHERE id=1 AND used=0 AND token_hash=?`, sha(token)).Scan(&ok)
		n, _ := s.CountUsers(ctx)
		if ok == 0 || n > 0 {
			return "", nil, fmt.Errorf("%w: invalid setup token", ports.ErrForbidden)
		}
		meta.Role = domain.RoleOwner
	case RegisterInvite:
		var role string
		if err := s.db.QueryRowContext(ctx, `SELECT role FROM invites WHERE token_hash=? AND used=0 AND expires_at>?`, sha(token), s.now().Unix()).Scan(&role); err != nil {
			return "", nil, fmt.Errorf("%w: invalid or expired invite", ports.ErrForbidden)
		}
		meta.Role = domain.Role(role)
	case RegisterAdd:
		u, err := s.loadWAUser(ctx, s.db, "id=?", userID)
		if err != nil {
			return "", nil, ports.ErrUnauthenticated
		}
		user, meta.UserID, meta.Name = u, u.ID, u.Name
	default:
		return "", nil, fmt.Errorf("%w: unknown registration purpose", ports.ErrInvalid)
	}
	if user == nil {
		if meta.Name == "" || len(meta.Name) > 80 {
			return "", nil, fmt.Errorf("%w: name must be 1-80 characters", ports.ErrInvalid)
		}
		meta.Handle = []byte(randomToken(24))
		user = &waUser{User: domain.User{Name: meta.Name}, handle: meta.Handle}
	} else {
		meta.Handle = user.handle
	}
	creation, sd, err := s.wa.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExclusions(webauthn.Credentials(user.creds).CredentialDescriptors()),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification: protocol.VerificationPreferred,
		}))
	if err != nil {
		return "", nil, err
	}
	id, err := s.saveCeremony(ctx, "register", meta.UserID, sd, meta)
	return id, creation, err
}

// FinishRegistration completes a registration. For setup and invite it creates the
// user and returns a new session id; for add it returns "".
func (s *Service) FinishRegistration(ctx context.Context, ceremonyID string, body []byte) (domain.User, string, error) {
	sd, rawMeta, err := s.takeCeremony(ctx, ceremonyID, "register")
	if err != nil {
		return domain.User{}, "", err
	}
	var meta regMeta
	if err := json.Unmarshal(rawMeta, &meta); err != nil {
		return domain.User{}, "", err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body))
	if err != nil {
		return domain.User{}, "", fmt.Errorf("%w: invalid passkey response", ports.ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.User{}, "", err
	}
	defer tx.Rollback()
	var u domain.User
	var sessionID string
	switch meta.Purpose {
	case RegisterSetup, RegisterInvite:
		if meta.Purpose == RegisterSetup {
			if err := s.consumeSetupToken(ctx, tx, meta.Token); err != nil {
				return u, "", err
			}
		} else if _, err := s.consumeInvite(ctx, tx, meta.Token); err != nil {
			return u, "", err
		}
		u = domain.User{ID: newID("usr_"), Name: meta.Name, Role: meta.Role, CreatedAt: s.now().UTC().Truncate(time.Second)}
		wu := &waUser{User: u, handle: meta.Handle}
		cred, err := s.wa.CreateCredential(wu, sd, parsed)
		if err != nil {
			return u, "", fmt.Errorf("%w: passkey verification failed: %v", ports.ErrForbidden, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO users(id, name, role, webauthn_id, created_at) VALUES (?, ?, ?, ?, ?)`, u.ID, u.Name, u.Role, meta.Handle, u.CreatedAt.Unix()); err != nil {
			return u, "", err
		}
		if err := insertPasskey(ctx, tx, u.ID, cred, s.now()); err != nil {
			return u, "", err
		}
		if sessionID, err = s.createSession(ctx, tx, u.ID); err != nil {
			return u, "", err
		}
	case RegisterAdd:
		wu, err := s.loadWAUser(ctx, tx, "id=?", meta.UserID)
		if err != nil {
			return u, "", ports.ErrUnauthenticated
		}
		cred, err := s.wa.CreateCredential(wu, sd, parsed)
		if err != nil {
			return u, "", fmt.Errorf("%w: passkey verification failed: %v", ports.ErrForbidden, err)
		}
		if err := insertPasskey(ctx, tx, wu.ID, cred, s.now()); err != nil {
			return u, "", err
		}
		u = wu.User
	}
	return u, sessionID, tx.Commit()
}

func insertPasskey(ctx context.Context, tx *sql.Tx, userID string, c *webauthn.Credential, now time.Time) error {
	data, _ := json.Marshal(c)
	_, err := tx.ExecContext(ctx, `INSERT INTO passkeys(id, user_id, data, created_at) VALUES (?, ?, ?, ?)`, c.ID, userID, string(data), now.Unix())
	return err
}

// BeginLogin starts a discoverable (usernameless) passkey login.
func (s *Service) BeginLogin(ctx context.Context) (string, *protocol.CredentialAssertion, error) {
	assertion, sd, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		return "", nil, err
	}
	id, err := s.saveCeremony(ctx, "login", "", sd, nil)
	return id, assertion, err
}

// FinishLogin verifies the assertion and returns a new session id.
func (s *Service) FinishLogin(ctx context.Context, ceremonyID string, body []byte) (domain.User, string, error) {
	sd, _, err := s.takeCeremony(ctx, ceremonyID, "login")
	if err != nil {
		return domain.User{}, "", err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
	if err != nil {
		return domain.User{}, "", fmt.Errorf("%w: invalid passkey response", ports.ErrInvalid)
	}
	var found *waUser
	cred, err := s.wa.ValidateDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		u, err := s.loadWAUser(ctx, s.db, "webauthn_id=?", userHandle)
		if err != nil {
			return nil, errors.New("unknown passkey")
		}
		found = u
		return u, nil
	}, sd, parsed)
	if err != nil || found == nil {
		return domain.User{}, "", ports.ErrUnauthenticated
	}
	if cred.Authenticator.CloneWarning {
		s.log.Warn("passkey sign counter went backwards: possible cloned authenticator", "user", found.ID)
		return domain.User{}, "", ports.ErrUnauthenticated
	}
	data, _ := json.Marshal(cred)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.User{}, "", err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE passkeys SET data=?, last_used_at=? WHERE id=?`, string(data), s.now().Unix(), cred.ID); err != nil {
		return domain.User{}, "", err
	}
	sid, err := s.createSession(ctx, tx, found.ID)
	if err != nil {
		return domain.User{}, "", err
	}
	return found.User, sid, tx.Commit()
}

var _ = http.StatusOK

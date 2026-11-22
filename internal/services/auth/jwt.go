package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
)

const (
	accessTokenTTL = time.Hour
	keyRotateAfter = 90 * 24 * time.Hour
	keyRetainAfter = 2 * accessTokenTTL // retired keys stay in JWKS until their tokens expire
)

type signingKey struct {
	kid       string
	priv      *ecdsa.PrivateKey
	createdAt time.Time
	retiredAt time.Time
}

type keySet struct {
	current *signingKey
	all     map[string]*signingKey // includes retired keys still in the JWKS window
	signer  jose.Signer
}

// SigningKeyInfo is metadata about the current signing key (security page).
type SigningKeyInfo struct {
	KID       string    `json:"kid"`
	CreatedAt time.Time `json:"created_at"`
	AgeDays   int       `json:"age_days"`
}

func (s *Service) loadKeys(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT kid, sealed_private, created_at, retired_at FROM signing_keys WHERE retired_at=0 OR retired_at>?`,
		s.now().Add(-keyRetainAfter).Unix())
	if err != nil {
		return err
	}
	ks := &keySet{all: map[string]*signingKey{}}
	for rows.Next() {
		var kid string
		var sealed []byte
		var c, r int64
		if err := rows.Scan(&kid, &sealed, &c, &r); err != nil {
			rows.Close()
			return err
		}
		der, err := s.box.Open(ctx, sealed, []byte("signing|"+kid))
		if err != nil {
			rows.Close()
			return fmt.Errorf("auth: cannot decrypt signing key %s (wrong master key?): %w", kid, err)
		}
		priv, err := x509.ParseECPrivateKey(der)
		if err != nil {
			rows.Close()
			return err
		}
		k := &signingKey{kid: kid, priv: priv, createdAt: time.Unix(c, 0)}
		if r != 0 {
			k.retiredAt = time.Unix(r, 0)
		}
		ks.all[kid] = k
		if r == 0 {
			ks.current = k
		}
	}
	rows.Close()
	if ks.current == nil || s.now().Sub(ks.current.createdAt) > keyRotateAfter {
		return s.RotateSigningKey(ctx)
	}
	return s.installKeys(ks)
}

func (s *Service) installKeys(ks *keySet) error {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: ks.current.priv},
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", ks.current.kid))
	if err != nil {
		return err
	}
	ks.signer = signer
	s.keysMu.Lock()
	s.keys = ks
	s.keysMu.Unlock()
	return nil
}

// RotateSigningKey creates a new signing key and retires the current one (AUTH-012).
func (s *Service) RotateSigningKey(ctx context.Context) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	kid := newID("k_")
	sealed, err := s.box.Seal(ctx, der, []byte("signing|"+kid))
	if err != nil {
		return err
	}
	pub, _ := json.Marshal(jose.JSONWebKey{Key: &priv.PublicKey, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"})
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE signing_keys SET retired_at=? WHERE retired_at=0`, now.Unix()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO signing_keys(kid, sealed_private, public_jwk, created_at) VALUES (?, ?, ?, ?)`, kid, sealed, string(pub), now.Unix()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	ks := &keySet{all: map[string]*signingKey{}}
	s.keysMu.RLock()
	if s.keys != nil {
		for k, v := range s.keys.all {
			if v.retiredAt.IsZero() {
				v.retiredAt = now
			}
			if now.Sub(v.retiredAt) < keyRetainAfter {
				ks.all[k] = v
			}
		}
	}
	s.keysMu.RUnlock()
	cur := &signingKey{kid: kid, priv: priv, createdAt: now}
	ks.all[kid], ks.current = cur, cur
	return s.installKeys(ks)
}

// SigningKey returns metadata for the current signing key.
func (s *Service) SigningKey() SigningKeyInfo {
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	c := s.keys.current
	return SigningKeyInfo{KID: c.kid, CreatedAt: c.createdAt.UTC(), AgeDays: int(s.now().Sub(c.createdAt).Hours() / 24)}
}

// JWKS returns the public keys (AUTH-012).
func (s *Service) JWKS() jose.JSONWebKeySet {
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	set := jose.JSONWebKeySet{}
	for _, k := range s.keys.all {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: &k.priv.PublicKey, KeyID: k.kid, Algorithm: string(jose.ES256), Use: "sig"})
	}
	return set
}

type accessClaims struct {
	jwt.Claims
	ClientID string `json:"client_id"`
	Profile  string `json:"profile"`
}

// issueAccessToken signs an access token (AUTH-010).
func (s *Service) issueAccessToken(id domain.Identity) (string, error) {
	s.keysMu.RLock()
	signer := s.keys.signer
	s.keysMu.RUnlock()
	now := s.now()
	c := accessClaims{
		Claims: jwt.Claims{
			Issuer: s.issuer, Subject: id.UserID, Audience: jwt.Audience{s.resource},
			IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
			Expiry: jwt.NewNumericDate(now.Add(accessTokenTTL)), ID: randomToken(12),
		},
		ClientID: id.ClientID, Profile: id.Profile,
	}
	return jwt.Signed(signer).Claims(c).Serialize()
}

// verifyAccessToken checks signature, kid, issuer, audience and expiry (AUTH-011).
func (s *Service) verifyAccessToken(tok string) (domain.Identity, error) {
	parsed, err := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(parsed.Headers) != 1 {
		return domain.Identity{}, ports.ErrUnauthenticated
	}
	s.keysMu.RLock()
	k := s.keys.all[parsed.Headers[0].KeyID]
	s.keysMu.RUnlock()
	if k == nil {
		return domain.Identity{}, ports.ErrUnauthenticated
	}
	var c accessClaims
	if err := parsed.Claims(&k.priv.PublicKey, &c); err != nil {
		return domain.Identity{}, ports.ErrUnauthenticated
	}
	if err := c.ValidateWithLeeway(jwt.Expected{Issuer: s.issuer, AnyAudience: jwt.Audience{s.resource}, Time: s.now()}, 30*time.Second); err != nil {
		return domain.Identity{}, ports.ErrUnauthenticated
	}
	if c.Subject == "" || c.ClientID == "" || c.Expiry == nil {
		return domain.Identity{}, errors.Join(ports.ErrUnauthenticated, errors.New("missing claims"))
	}
	return domain.Identity{UserID: c.Subject, ClientID: c.ClientID, Profile: c.Profile}, nil
}

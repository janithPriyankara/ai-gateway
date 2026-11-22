// Package testutil has helpers shared by tests: a software WebAuthn authenticator.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// softAuthenticator is a minimal software WebAuthn authenticator (ES256, "none"
// attestation) so passkey ceremonies can be tested end to end without a browser.
type SoftAuthenticator struct {
	t      testing.TB
	origin string
	rpID   string
	key    *ecdsa.PrivateKey
	credID []byte
	Handle []byte
	count  uint32
}

// NewSoftAuthenticator returns an ES256 authenticator for origin / rpID.
func NewSoftAuthenticator(t testing.TB, origin, rpID string) *SoftAuthenticator {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	rand.Read(id)
	return &SoftAuthenticator{t: t, origin: origin, rpID: rpID, key: k, credID: id}
}

var b64 = base64.RawURLEncoding

func (a *SoftAuthenticator) clientData(typ, challenge string) []byte {
	cd, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return cd
}

func (a *SoftAuthenticator) authData(flags byte, attested []byte) []byte {
	rp := sha256.Sum256([]byte(a.rpID))
	out := append([]byte{}, rp[:]...)
	out = append(out, flags)
	cnt := make([]byte, 4)
	binary.BigEndian.PutUint32(cnt, a.count)
	out = append(out, cnt...)
	return append(out, attested...)
}

// options extracts challenge and (for creation) user handle from begin-ceremony options.
func parseOptions(t testing.TB, opts any) (challenge string, userID string) {
	raw, _ := json.Marshal(opts)
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	return o.PublicKey.Challenge, o.PublicKey.User.ID
}

// Register answers a navigator.credentials.create() call.
func (a *SoftAuthenticator) Register(opts any) []byte {
	challenge, uid := parseOptions(a.t, opts)
	a.Handle, _ = b64.DecodeString(uid)
	x := a.key.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.key.PublicKey.Y.FillBytes(make([]byte, 32))
	cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	attested := make([]byte, 16) // AAGUID
	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(a.credID)))
	attested = append(attested, l...)
	attested = append(attested, a.credID...)
	attested = append(attested, cose...)
	ad := a.authData(0x01|0x04|0x40, attested) // UP | UV | AT
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})
	resp, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", challenge)),
			"attestationObject": b64.EncodeToString(att),
		},
	})
	return resp
}

// Login answers a navigator.credentials.get() call.
func (a *SoftAuthenticator) Login(opts any) []byte {
	challenge, _ := parseOptions(a.t, opts)
	a.count++
	ad := a.authData(0x01|0x04, nil)
	cd := a.clientData("webauthn.get", challenge)
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	resp, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(ad),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString(a.Handle),
		},
	})
	return resp
}

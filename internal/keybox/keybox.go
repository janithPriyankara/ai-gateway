// Package keybox implements envelope encryption for secrets at rest.
//
// Every secret is encrypted with its own random 256-bit data key (DEK) using
// AES-256-GCM. The DEK is then wrapped by a master key (KEK) that lives in a
// pluggable Provider (OS keychain, TPM, file secret, cloud KMS, …).
//
// Blob layout (version 1):
//
//	[1]  version (0x01)
//	[2]  big-endian length W of the wrapped DEK
//	[W]  wrapped DEK (provider-specific)
//	[12] payload nonce
//	[..] AES-256-GCM ciphertext + tag, AAD = version || caller AAD
//
// The wrapped DEK is deliberately not part of the payload AAD so that a KEK
// rotation (Rewrap) can replace it without touching the encrypted payload.
// Tampering with the wrapped DEK is still detected because unwrapping is
// itself authenticated.
package keybox

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

const (
	version1  = 0x01
	dekSize   = 32
	nonceSize = 12
)

// ErrDecrypt is returned for any failure to open a blob. It never carries detail
// that could help an attacker or leak key material (KEY-010).
var ErrDecrypt = errors.New("keybox: cannot decrypt secret (wrong key, wrong owner or corrupted data)")

// Box seals and opens secrets with a Provider.
type Box struct{ p Provider }

// New returns a Box backed by p.
func New(p Provider) *Box { return &Box{p: p} }

// Provider returns the underlying key provider.
func (b *Box) Provider() Provider { return b.p }

// Seal encrypts plaintext under a fresh DEK. aad binds the secret to its context
// (for example "user|server") so it cannot be moved to another owner (KEY-003).
func (b *Box) Seal(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	defer zero(dek)
	wrapped, err := b.p.Wrap(ctx, dek)
	if err != nil {
		return nil, errors.New("keybox: wrapping data key failed")
	}
	if len(wrapped) > 0xFFFF {
		return nil, errors.New("keybox: wrapped key too large")
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 3+len(wrapped)+nonceSize+len(plaintext)+gcm.Overhead())
	out = append(out, version1, 0, 0)
	binary.BigEndian.PutUint16(out[1:3], uint16(len(wrapped)))
	out = append(out, wrapped...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, payloadAAD(aad))
	return out, nil
}

// Open decrypts a blob produced by Seal with the same aad.
func (b *Box) Open(ctx context.Context, blob, aad []byte) ([]byte, error) {
	wrapped, nonce, ok, ct := parse(blob)
	if !ok {
		return nil, ErrDecrypt
	}
	dek, err := b.p.Unwrap(ctx, wrapped)
	if err != nil || len(dek) != dekSize {
		return nil, ErrDecrypt
	}
	defer zero(dek)
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, ErrDecrypt
	}
	pt, err := gcm.Open(nil, nonce, ct, payloadAAD(aad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Rewrap re-wraps the blob's DEK for the target box's provider without
// decrypting the payload (KEY-011). Used for master-key rotation.
func (b *Box) Rewrap(ctx context.Context, blob []byte, target *Box) ([]byte, error) {
	wrapped, nonce, ok, ct := parse(blob)
	if !ok {
		return nil, ErrDecrypt
	}
	dek, err := b.p.Unwrap(ctx, wrapped)
	if err != nil {
		return nil, ErrDecrypt
	}
	defer zero(dek)
	nw, err := target.p.Wrap(ctx, dek)
	if err != nil {
		return nil, errors.New("keybox: wrapping data key failed")
	}
	out := make([]byte, 0, 3+len(nw)+nonceSize+len(ct))
	out = append(out, version1, 0, 0)
	binary.BigEndian.PutUint16(out[1:3], uint16(len(nw)))
	out = append(out, nw...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func parse(blob []byte) (wrapped, nonce []byte, ok bool, ct []byte) {
	if len(blob) < 3 || blob[0] != version1 {
		return nil, nil, false, nil
	}
	w := int(binary.BigEndian.Uint16(blob[1:3]))
	if len(blob) < 3+w+nonceSize+16 {
		return nil, nil, false, nil
	}
	wrapped = blob[3 : 3+w]
	nonce = blob[3+w : 3+w+nonceSize]
	ct = blob[3+w+nonceSize:]
	return wrapped, nonce, true, ct
}

func payloadAAD(aad []byte) []byte {
	out := make([]byte, 0, 1+len(aad))
	out = append(out, version1)
	return append(out, aad...)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

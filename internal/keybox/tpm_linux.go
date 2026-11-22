//go:build linux

package keybox

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// openTPM seals a random KEK to the TPM2 with systemd-creds (KEY-012).
func openTPM(ctx context.Context, cfg Config) (Provider, error) {
	bin, err := exec.LookPath("systemd-creds")
	if err != nil {
		return nil, errors.New("keybox: linux-tpm needs systemd-creds (systemd 250+)")
	}
	if cfg.DataDir == "" {
		return nil, errors.New("keybox: linux-tpm needs a data directory")
	}
	path := filepath.Join(cfg.DataDir, "keybox.tpm2.cred")
	if sealed, err := os.ReadFile(path); err == nil {
		cmd := exec.CommandContext(ctx, bin, "decrypt", "--name=mcp-gateway-kek", "-", "-")
		cmd.Stdin = bytes.NewReader(sealed)
		kek, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("keybox: TPM unseal failed (different machine or TPM reset?): %v", err)
		}
		return newAEADProvider("linux-tpm", StrengthStrong, kek)
	}
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, bin, "encrypt", "--with-key=tpm2", "--name=mcp-gateway-kek", "-", "-")
	cmd.Stdin = bytes.NewReader(kek)
	sealed, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("keybox: TPM2 seal failed (no TPM?): %v", err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, sealed, 0o600); err != nil {
		return nil, err
	}
	return newAEADProvider("linux-tpm", StrengthStrong, kek)
}

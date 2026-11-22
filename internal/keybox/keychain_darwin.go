//go:build darwin

package keybox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const keychainService = "mcp-gateway"

// openKeychain stores a random KEK in the user's login keychain (KEY-008).
// The secret is passed to `security` over stdin (interactive mode), never argv,
// so it does not appear in the process list.
func openKeychain(ctx context.Context, cfg Config) (Provider, error) {
	account := cfg.KeychainAccount
	if account == "" {
		account = "master-key"
	}
	out, err := exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password",
		"-s", keychainService, "-a", account, "-w").Output()
	if err == nil {
		k, derr := hex.DecodeString(strings.TrimSpace(string(out)))
		if derr != nil || len(k) != 32 {
			return nil, errors.New("keybox: keychain item is not a valid master key")
		}
		return newAEADProvider("macos-keychain", StrengthStrong, k)
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 44 { // 44 = item not found
		return nil, fmt.Errorf("keybox: keychain unavailable: %v", err)
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/security", "-i")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("add-generic-password -s %s -a %s -l %q -w %s -U\n",
		keychainService, account, "mcp-gateway master key", hex.EncodeToString(k)))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("keybox: storing master key in keychain failed: %v", err)
	}
	return newAEADProvider("macos-keychain", StrengthStrong, k)
}

func deleteKeychainItem(account string) error {
	return exec.Command("/usr/bin/security", "delete-generic-password", "-s", keychainService, "-a", account).Run()
}

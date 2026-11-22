//go:build !darwin

package keybox

import (
	"context"
	"errors"
)

func openKeychain(context.Context, Config) (Provider, error) {
	return nil, errors.New("keybox: macos-keychain is only available on macOS")
}

func deleteKeychainItem(string) error { return nil }

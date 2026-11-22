//go:build windows

package keybox

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"unsafe"
)

func dpapi(in []byte, protect bool) ([]byte, error) {
	if len(in) == 0 {
		return nil, errors.New("empty input")
	}
	var out windows.DataBlob
	blob := windows.DataBlob{Size: uint32(len(in)), Data: &in[0]}
	var err error
	if protect {
		err = windows.CryptProtectData(&blob, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(&blob, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

// openDPAPI protects a random KEK with DPAPI for the current user (KEY-013).
func openDPAPI(_ context.Context, cfg Config) (Provider, error) {
	if cfg.DataDir == "" {
		return nil, errors.New("keybox: windows-dpapi needs a data directory")
	}
	path := filepath.Join(cfg.DataDir, "keybox.dpapi")
	if prot, err := os.ReadFile(path); err == nil {
		kek, err := dpapi(prot, false)
		if err != nil {
			return nil, fmt.Errorf("keybox: DPAPI unprotect failed (different Windows user?): %v", err)
		}
		return newAEADProvider("windows-dpapi", StrengthStrong, kek)
	}
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		return nil, err
	}
	prot, err := dpapi(kek, true)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, prot, 0o600); err != nil {
		return nil, err
	}
	return newAEADProvider("windows-dpapi", StrengthStrong, kek)
}

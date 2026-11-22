//go:build !windows

package keybox

import (
	"context"
	"errors"
)

func openDPAPI(context.Context, Config) (Provider, error) {
	return nil, errors.New("keybox: windows-dpapi is only available on Windows")
}

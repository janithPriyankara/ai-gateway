//go:build !linux

package keybox

import (
	"context"
	"errors"
)

func openTPM(context.Context, Config) (Provider, error) {
	return nil, errors.New("keybox: linux-tpm is only available on Linux")
}

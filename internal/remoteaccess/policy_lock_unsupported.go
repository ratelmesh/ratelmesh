//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows

package remoteaccess

import (
	"errors"
	"os"
)

func lockPolicyFile(_ *os.File) error {
	return errors.New("cross-process file locking is unsupported")
}

func unlockPolicyFile(_ *os.File) error {
	return nil
}

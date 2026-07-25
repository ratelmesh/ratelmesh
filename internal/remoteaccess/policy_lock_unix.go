//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package remoteaccess

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockPolicyFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX)
}

func unlockPolicyFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}

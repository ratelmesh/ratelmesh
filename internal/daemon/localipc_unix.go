//go:build !windows

package daemon

import (
	"context"
	"net"
	"os"
)

func listenLocal(path string) (net.Listener, func(), error) {
	// Remove a stale socket from a previous run.
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, func() {}, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		_ = os.Remove(path)
		return nil, func() {}, err
	}
	return ln, func() { _ = os.Remove(path) }, nil
}

func dialLocal(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}

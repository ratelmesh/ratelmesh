//go:build windows

package daemon

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
)

// localPipeSDDL grants full access only to LocalSystem, administrators, and the
// pipe owner (the interactive/service account running ratelmeshd).
const localPipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)"

func listenLocal(path string) (net.Listener, func(), error) {
	ln, err := winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: localPipeSDDL,
		MessageMode:        false,
		InputBufferSize:    64 << 10,
		OutputBufferSize:   64 << 10,
	})
	if err != nil {
		return nil, func() {}, err
	}
	return ln, func() {}, nil
}

func dialLocal(ctx context.Context, path string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, path)
}

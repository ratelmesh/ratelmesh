//go:build !wgreal

package wgengine

import "log/slog"

// New returns the default engine for builds without the `wgreal` tag: the
// rootless stub. Build with `-tags wgreal` to select the real data plane.
func New(log *slog.Logger) Engine { return NewStub(log) }

// OwnsListenPort reports whether the active engine binds the WireGuard
// ListenPort itself. The stub does not, so the disco responder may use it.
func OwnsListenPort() bool { return false }

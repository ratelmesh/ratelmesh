package diagnose

import (
	"net"
	"net/http"
	"time"
)

// NewStdNetDeps returns Deps backed by the standard library's non-privileged
// networking primitives — a *net.Dialer, the default *net.Resolver and an
// *http.Client — which satisfy the Dialer, Resolver and HTTPDoer seams
// directly. It is the default adapter for the reachability probes (coordinator,
// relay, exit egress, IPv4/IPv6, DNS, media) and needs no elevated privilege.
//
// It intentionally supplies no PathMTUProber: active path-MTU discovery needs
// platform-specific, privileged sockets that belong in a platform adapter, not
// here. With no prober injected the MTU probe falls back to the link MTU carried
// in the snapshot.
//
// This is real product code, not a test double: the daemon can use it as-is, or
// wrap it (for example to pin dialing to the tunnel interface) before injecting.
func NewStdNetDeps() Deps {
	dialer := &net.Dialer{
		// A keep-alive-free, context-bounded dialer; the probes impose the
		// actual per-dial deadline through the context they pass.
		KeepAlive: -1,
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	client := &http.Client{
		Transport: transport,
		// No client-level timeout: each probe bounds its request via context.
		// Do not chase redirects — a probe cares whether the target answers,
		// and following redirects could reach an unrelated host.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resolver := net.DefaultResolver
	return Deps{
		Dialer:   dialer,
		Resolver: resolver,
		HTTP:     client,
		QUIC:     stdQUICProber{resolver: resolver},
		Clock:    SystemClock{},
	}
}

package control

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/transport"
)

// NewCamoClient builds a coord client whose HTTP connection is carried inside a
// censorship-resistant transport (e.g. WSS ws-camo) instead of plain HTTPS.
//
// Why this exists: the control plane normally reaches the coordinator over
// ordinary TLS to a Cloudflare-fronted host. That is exactly the flow an SNI/DPI
// censor throttles — a China client can have a healthy coordinator (verified
// reachable elsewhere) yet never register. The relay already survives this by
// riding WSS (real TLS + a WebSocket upgrade, SNI hidden with ECH) so it looks
// like ordinary HTTPS to a CDN. This routes the coordinator's HTTP/JSON over that
// same transport.
//
// tr is the client side of the camouflage transport (typically
// transport.NewWSSCamoClient(frontDoorHost)). frontDoor is the "host:port" the
// transport actually dials — the CDN edge / front door, which may differ from the
// coordinator's own hostname. baseURL stays the coordinator's URL so the HTTP
// Host header and TLS-independent request routing are unchanged; only the carrier
// underneath is swapped.
func NewCamoClient(baseURL, authKey string, tr transport.Transport, frontDoor string) *Client {
	c := NewClient(baseURL, authKey)
	c.hc = &http.Client{
		Timeout:   c.hc.Timeout,
		Transport: camouflageTransport(tr, frontDoor),
	}
	return c
}

// camouflageTransport returns an http.Transport that, for every connection,
// dials the front door over TCP and wraps it in tr before any HTTP byte is sent.
//
// It hangs the transport off DialTLSContext, not DialContext: tr already performs
// the TLS handshake to the CDN edge and hands back a plaintext-carrying stream, so
// net/http must speak HTTP directly over that stream and must NOT add a second TLS
// layer. Because the returned conn is not a *tls.Conn, net/http negotiates no
// ALPN and falls back to HTTP/1.1 — which is what the de-framing origin bridge on
// the far side expects.
func camouflageTransport(tr transport.Transport, frontDoor string) *http.Transport {
	return &http.Transport{
		// The addr net/http derives from the coordinator URL is deliberately
		// ignored: the carrier always dials the front door, and the coordinator
		// hostname survives only in the HTTP Host header the origin forwards.
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			raw, err := d.DialContext(ctx, "tcp", frontDoor)
			if err != nil {
				return nil, fmt.Errorf("camo: dial front door %s: %w", frontDoor, err)
			}
			conn, err := tr.Client(raw)
			if err != nil {
				_ = raw.Close()
				return nil, fmt.Errorf("camo: %s handshake: %w", tr.Name(), err)
			}
			return conn, nil
		},
		// A camouflaged tunnel is more expensive to set up than a bare socket, so
		// keep idle carriers around a little rather than re-handshaking per poll.
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          4,
		ExpectContinueTimeout: time.Second,
	}
}

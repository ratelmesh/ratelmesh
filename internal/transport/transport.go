// Package transport is RatelMesh's pluggable obfuscation layer (DESIGN.md §8). It
// sits *below* WireGuard and *above* the raw socket: WireGuard keeps doing the
// encryption and routing, while a Transport reshapes the bytes on the wire so an
// active censor's DPI cannot fingerprint them.
//
// The interface is the extension point the design calls for. This milestone
// ships two implementations:
//
//   - Plain: identity passthrough, for uncensored networks (best performance).
//   - Obfs:  a "look-like-nothing" obfuscator (ChaCha20 keystream + randomized
//     handshake padding) that removes fixed byte signatures.
//
// Stronger transports named in DESIGN.md §8.2 — REALITY (borrowed real-TLS
// fingerprint) and Hysteria2 (QUIC) — implement this same interface and are the
// production defaults inside the GFW; Obfs is the dependency-free baseline that
// proves the plumbing end to end. The control plane selects which transport a
// given link uses.
package transport

import "net"

// Transport wraps a raw connection with an obfuscation scheme. Client wraps the
// dialing side; Server wraps the accepting side. Both must agree out of band on
// the transport and its parameters (e.g. the pre-shared obfuscation secret).
type Transport interface {
	// Name identifies the transport (e.g. "plain", "obfs").
	Name() string
	// Client performs any client-side handshake and returns an obfuscated conn.
	Client(raw net.Conn) (net.Conn, error)
	// Server performs any server-side handshake and returns a de-obfuscated conn.
	Server(raw net.Conn) (net.Conn, error)
}

// Plain is the identity transport: no obfuscation, used on open networks.
type Plain struct{}

func (Plain) Name() string                          { return "plain" }
func (Plain) Client(raw net.Conn) (net.Conn, error) { return raw, nil }
func (Plain) Server(raw net.Conn) (net.Conn, error) { return raw, nil }

// New returns a transport by name, or Plain for unknown/empty names. For
// "tlscamo" it returns the client side (camouflaging as HTTPS to `secret` as the
// SNI); a server should construct NewTLSCamoServer explicitly since it generates
// a certificate and can fail.
func New(name string, secret []byte) Transport {
	switch name {
	case "obfs":
		return NewObfs(secret)
	case "tlscamo":
		return NewTLSCamoClient(string(secret), nil)
	case "wscamo":
		return NewWSCamoClient(string(secret))
	default:
		return Plain{}
	}
}

package transport

// WSSCamo carries ws-camo INSIDE real TLS: the client speaks HTTPS (a TLS
// handshake followed by a WebSocket upgrade) to the endpoint, so on the wire it
// is indistinguishable from an ordinary HTTPS/WebSocket connection — the SNI/Host
// is encrypted and the flow blends in with the vast amount of normal web traffic
// to the same CDN (DESIGN.md §8). This is the censorship-resistant upgrade over
// plain ws-camo (whose Host header rides in cleartext on :80).
//
// It is built to ride a TLS-terminating CDN such as Cloudflare: the CLIENT does
// verifying TLS to the edge (which holds a valid cert for serverName), and the
// edge forwards a PLAIN WebSocket to a ws-camo origin — so the relay behind the
// CDN needs no change. A self-hosted (no-CDN) server side is also provided
// (self-signed) for direct deployments and tests.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	"github.com/ratelmesh/ratelmesh/internal/pqcrypto"
)

const wssCamoName = "wss"

// WSSCamo is the TLS+WebSocket transport. Build the dialing side with
// NewWSSCamoClient and (for direct/self-hosted use) the accepting side with
// NewWSSCamoServer.
type WSSCamo struct {
	serverName string
	roots      *x509.CertPool   // client verifies against these; nil = system roots
	cert       *tls.Certificate // server presents this; nil = client-only
	ws         *WSCamo          // the inner WebSocket-camouflage layer
	noECH      bool             // skip the ECH-config fetch (tests / self-signed servers)
}

// NewWSSCamoClient builds the dialing side: verifying TLS (system roots) with
// serverName as SNI, then a ws-camo WebSocket upgrade with the same Host. Point
// it at a CDN edge (e.g. relay.example.com:443) that fronts a ws-camo origin.
func NewWSSCamoClient(serverName string) *WSSCamo {
	return &WSSCamo{serverName: serverName, ws: NewWSCamoClient(serverName)}
}

// NewWSSCamoServer builds a self-hosted accepting side (self-signed TLS +
// ws-camo). Not needed behind a TLS-terminating CDN, which delivers plain
// ws-camo to the origin; used for direct deployments and tests.
func NewWSSCamoServer(serverName string) (*WSSCamo, error) {
	cert, err := selfSignedCert(serverName)
	if err != nil {
		return nil, err
	}
	return &WSSCamo{serverName: serverName, cert: &cert, ws: NewWSCamoServer()}, nil
}

// Name identifies the transport.
func (*WSSCamo) Name() string { return wssCamoName }

// Client performs the TLS handshake (verifying the edge certificate) and then
// the ws-camo WebSocket upgrade over the encrypted connection.
func (w *WSSCamo) Client(raw net.Conn) (net.Conn, error) {
	cfg := pqcrypto.TLSConfig()
	cfg.ServerName = w.serverName
	cfg.RootCAs = w.roots
	// Best-effort ECH: if the endpoint publishes an ECHConfigList, encrypt the SNI
	// so the target domain is hidden on the wire. If it can't be fetched (e.g. DoH
	// blocked), fall back to a normal TLS handshake with a plaintext SNI.
	if !w.noECH {
		if ech := fetchECHConfigList(context.Background(), w.serverName); len(ech) > 0 {
			cfg.EncryptedClientHelloConfigList = ech
		}
	}
	conn := tls.Client(raw, cfg)
	if err := conn.Handshake(); err != nil {
		return nil, fmt.Errorf("wss: tls client handshake: %w", err)
	}
	return w.ws.Client(conn)
}

// Server terminates TLS with the configured cert and then accepts the ws-camo
// handshake. Behind a TLS-terminating CDN this is unused (the origin runs plain
// ws-camo); it exists for self-hosted/direct deployments and tests.
func (w *WSSCamo) Server(raw net.Conn) (net.Conn, error) {
	if w.cert == nil {
		return nil, errors.New("wss: no server cert (origin runs plain ws-camo behind a TLS-terminating CDN)")
	}
	cfg := pqcrypto.TLSConfig()
	cfg.Certificates = []tls.Certificate{*w.cert}
	conn := tls.Server(raw, cfg)
	if err := conn.Handshake(); err != nil {
		return nil, fmt.Errorf("wss: tls server handshake: %w", err)
	}
	return w.ws.Server(conn)
}

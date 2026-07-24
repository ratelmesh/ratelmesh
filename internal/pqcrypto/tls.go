// Package pqcrypto centralizes RatelMesh's post-quantum cryptographic policy.
// Keeping the policy in one package prevents individual transports from
// accidentally re-enabling classical-only downgrade paths.
package pqcrypto

import (
	"crypto/tls"
	"net/http"
)

// TLSConfig returns a TLS 1.3-only configuration whose sole key exchange is
// X25519MLKEM768. This is deliberately stricter than Go's safe default: the
// default advertises hybrid groups first but permits a classical-only fallback.
func TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	}
}

// HTTPTransport returns an http.Transport that preserves Go's proxy and HTTP/2
// behavior while enforcing RatelMesh's post-quantum policy for HTTPS requests.
// Plain HTTP remains available for loopback tests and private origin hops.
func HTTPTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = TLSConfig()
	return t
}

// Apply copies the strict protocol policy into cfg without changing identity,
// roots, certificates, ECH, ALPN, or application-specific verification fields.
func Apply(cfg *tls.Config) {
	cfg.MinVersion = tls.VersionTLS13
	cfg.MaxVersion = tls.VersionTLS13
	cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
}

package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/pqcrypto"
)

// TLSCamo camouflages the link as ordinary HTTPS by wrapping it in a *real* TLS
// 1.3 session (crypto/tls). To a censor's DPI the flow is indistinguishable from
// a normal browser-to-website handshake: a genuine ClientHello with SNI, a
// certificate exchange, and an encrypted record layer above it. WireGuard's own
// ciphertext rides inside the TLS records, so no WireGuard byte signature ever
// reaches the wire.
//
// This is the dependency-free cousin of REALITY (DESIGN.md §8.2): REALITY steals
// a real site's TLS fingerprint to survive active probing, whereas TLSCamo
// presents its own self-signed certificate. That is enough to defeat passive,
// signature-based DPI but NOT a prober who connects and inspects the cert; use
// REALITY or a genuinely-issued certificate where active probing is a concern.
//
// Trust model:
//   - The server side generates a self-signed ECDSA P-256 certificate at runtime
//     for serverName (see NewTLSCamoServer). Its PEM is exposed via CertPEM so
//     the client can pin it out of band.
//   - The client side (NewTLSCamoClient) requires that PEM and verifies the
//     server against a private root. An unpinned connection fails closed:
//     WireGuard would still protect tunneled packets, but the Relay admission
//     exchange occurs outside WireGuard and must not be exposed to an active
//     intermediary.
//
// Both sides must agree out of band on serverName (it becomes the SNI/ServerName
// so the connection looks like a real site of that name).
type TLSCamo struct {
	serverName string
	cert       tls.Certificate // server side: the self-signed leaf; unset on client
	roots      *x509.CertPool  // client side: pinned root(s)
	pinned     bool            // client side: true when a cert was pinned
	pinErr     error           // non-nil when a caller supplied an invalid pin
}

const (
	tlsCamoName     = "tlscamo"
	tlsCamoExpiry   = 825 * 24 * time.Hour // ~27 months, within CA/B leaf limits
	tlsCamoBackdate = time.Hour            // tolerate mild clock skew
)

// NewTLSCamoServer builds the accepting side of a TLS-camouflaged transport,
// generating a fresh self-signed ECDSA P-256 certificate for serverName. Expose
// its PEM with CertPEM so a client can pin it.
func NewTLSCamoServer(serverName string) (*TLSCamo, error) {
	if serverName == "" {
		return nil, errors.New("tlscamo: server name must not be empty")
	}
	cert, err := selfSignedCert(serverName)
	if err != nil {
		return nil, err
	}
	return &TLSCamo{serverName: serverName, cert: cert}, nil
}

// NewTLSCamoClient builds the dialing side. pinCert must be a non-empty
// PEM-encoded certificate; the server must present that certificate and a
// matching server name. Callers without a stable pin should use WSS backed by a
// publicly trusted certificate instead.
func NewTLSCamoClient(serverName string, pinCert []byte) *TLSCamo {
	t := &TLSCamo{serverName: serverName}
	if len(pinCert) == 0 {
		t.pinErr = errors.New("tlscamo: certificate pin is required; use authenticated WSS when no stable pin is available")
		return t
	}
	pool := x509.NewCertPool()
	if pool.AppendCertsFromPEM(pinCert) {
		t.roots = pool
		t.pinned = true
	} else {
		t.pinErr = errors.New("tlscamo: supplied certificate pin is not valid PEM")
	}
	return t
}

// Name identifies the transport.
func (*TLSCamo) Name() string { return tlsCamoName }

// Client wraps the dialing side in a TLS client session and completes the
// handshake before returning.
func (t *TLSCamo) Client(raw net.Conn) (net.Conn, error) {
	if t.pinErr != nil {
		return nil, t.pinErr
	}
	if !t.pinned || t.roots == nil {
		return nil, errors.New("tlscamo: certificate pin is required; use authenticated WSS when no stable pin is available")
	}
	cfg := pqcrypto.TLSConfig()
	cfg.ServerName = t.serverName
	cfg.RootCAs = t.roots
	conn := tls.Client(raw, cfg)
	if err := conn.Handshake(); err != nil {
		return nil, fmt.Errorf("tlscamo: client handshake: %w", err)
	}
	return conn, nil
}

// Server wraps the accepting side in a TLS server session using the self-signed
// certificate and completes the handshake before returning.
func (t *TLSCamo) Server(raw net.Conn) (net.Conn, error) {
	cfg := pqcrypto.TLSConfig()
	cfg.Certificates = []tls.Certificate{t.cert}
	conn := tls.Server(raw, cfg)
	if err := conn.Handshake(); err != nil {
		return nil, fmt.Errorf("tlscamo: server handshake: %w", err)
	}
	return conn, nil
}

// CertPEM returns the PEM-encoded leaf certificate this transport presents as a
// TLS server, so a client can pin it via NewTLSCamoClient. It returns nil on the
// client side (which holds no certificate).
func (t *TLSCamo) CertPEM() []byte {
	if len(t.cert.Certificate) == 0 {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: t.cert.Certificate[0],
	})
}

// selfSignedCert mints a fresh self-signed ECDSA P-256 leaf for serverName,
// valid for both DNS-name and (if serverName parses as one) IP SANs.
func selfSignedCert(serverName string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlscamo: generate key: %w", err)
	}

	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlscamo: serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: serverName},
		NotBefore:             now.Add(-tlsCamoBackdate),
		NotAfter:              now.Add(tlsCamoExpiry),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(serverName); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{serverName}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlscamo: create cert: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        tmpl,
	}, nil
}

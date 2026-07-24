package pqcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestTLSConfigRequiresHybridMLKEM(t *testing.T) {
	cfg := TLSConfig()
	if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("TLS versions = %x..%x, want TLS 1.3 only", cfg.MinVersion, cfg.MaxVersion)
	}
	if len(cfg.CurvePreferences) != 1 || cfg.CurvePreferences[0] != tls.X25519MLKEM768 {
		t.Fatalf("curve preferences = %v, want only X25519MLKEM768", cfg.CurvePreferences)
	}
}

func testTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestTLSHandshakeNegotiatesOnlyX25519MLKEM768(t *testing.T) {
	serverRaw, clientRaw := net.Pipe()
	defer serverRaw.Close()
	defer clientRaw.Close()
	serverCfg := TLSConfig()
	serverCfg.Certificates = []tls.Certificate{testTLSCertificate(t)}
	clientCfg := TLSConfig()
	clientCfg.InsecureSkipVerify = true // test certificate only
	server := tls.Server(serverRaw, serverCfg)
	client := tls.Client(clientRaw, clientCfg)
	errCh := make(chan error, 1)
	go func() { errCh <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if got := client.ConnectionState().CurveID; got != tls.X25519MLKEM768 {
		t.Fatalf("negotiated %v, want X25519MLKEM768", got)
	}
}

func TestTLSHandshakeRejectsClassicalOnlyPeer(t *testing.T) {
	serverRaw, clientRaw := net.Pipe()
	defer serverRaw.Close()
	defer clientRaw.Close()
	serverCfg := TLSConfig()
	serverCfg.Certificates = []tls.Certificate{testTLSCertificate(t)}
	serverCfg.CurvePreferences = []tls.CurveID{tls.X25519}
	clientCfg := TLSConfig()
	clientCfg.InsecureSkipVerify = true
	server := tls.Server(serverRaw, serverCfg)
	client := tls.Client(clientRaw, clientCfg)
	errCh := make(chan error, 1)
	go func() { errCh <- server.Handshake() }()
	if err := client.Handshake(); err == nil {
		t.Fatal("strict post-quantum client accepted classical-only server")
	}
	<-errCh
}

func TestHTTPTransportDoesNotMutateDefault(t *testing.T) {
	tr := HTTPTransport()
	if tr == http.DefaultTransport || tr.TLSClientConfig == nil {
		t.Fatal("HTTPTransport did not clone and configure the default transport")
	}
}

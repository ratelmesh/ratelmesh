package transport

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
)

// tlsRoundTrip runs a client->server->client exchange over a *real* TCP
// listener (TLS handshakes need a real bidirectional socket; net.Pipe's
// synchronous semantics deadlock the handshake). It returns what the server
// received and the raw bytes observed on the wire in the client->server
// direction.
func tlsRoundTrip(t *testing.T, client, server *TLSCamo, payload []byte) (received, wire []byte) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var (
		wg        sync.WaitGroup
		serverGot []byte
		serverErr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		raw, err := ln.Accept()
		if err != nil {
			serverErr = err
			return
		}
		defer raw.Close()
		sc, err := server.Server(raw)
		if err != nil {
			serverErr = err
			return
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(sc, buf); err != nil {
			serverErr = err
			return
		}
		serverGot = buf
		// Echo it straight back so the client can confirm the full round trip.
		if _, err := sc.Write(buf); err != nil {
			serverErr = err
		}
	}()

	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawClient.Close()

	// Tap the client->server direction: this is the plaintext a censor's DPI
	// would inspect on the wire.
	tap := &tapConn{Conn: rawClient}

	cc, err := client.Client(tap)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := cc.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(cc, echo); err != nil {
		t.Fatalf("client read echo: %v", err)
	}

	wg.Wait()
	if serverErr != nil {
		t.Fatalf("server: %v", serverErr)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("echo got %q, want %q", echo, payload)
	}
	return serverGot, tap.Bytes()
}

func TestTLSCamoRoundTripPinned(t *testing.T) {
	server, err := NewTLSCamoServer("cloud.example.com")
	if err != nil {
		t.Fatalf("NewTLSCamoServer: %v", err)
	}
	pem := server.CertPEM()
	if len(pem) == 0 {
		t.Fatal("CertPEM returned nothing on the server side")
	}
	client := NewTLSCamoClient("cloud.example.com", pem)
	if !client.pinned {
		t.Fatal("client should have pinned the supplied cert")
	}

	payload := []byte("this-is-a-wireguard-ciphertext-packet")
	got, wire := tlsRoundTrip(t, client, server, payload)

	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip got %q, want %q", got, payload)
	}
	// The application payload must never appear in cleartext: the TLS record
	// layer encrypts everything after the handshake.
	if bytes.Contains(wire, payload) {
		t.Error("tlscamo leaked plaintext on the wire (TLS should encrypt it)")
	}
	// Sanity: a real TLS ClientHello starts the flow (record type 0x16 =
	// handshake, version 0x0301 in the record header for TLS 1.x).
	if len(wire) < 3 || wire[0] != 0x16 {
		t.Errorf("wire did not begin with a TLS handshake record, got % x", wire[:min(3, len(wire))])
	}
}

func TestTLSCamoRoundTripInsecure(t *testing.T) {
	server, err := NewTLSCamoServer("insecure.example.com")
	if err != nil {
		t.Fatalf("NewTLSCamoServer: %v", err)
	}
	// nil pinCert => InsecureSkipVerify path (test/dev only).
	client := NewTLSCamoClient("insecure.example.com", nil)
	if client.pinned {
		t.Fatal("client should not be pinned when no cert supplied")
	}

	payload := []byte("hello over unpinned tls")
	got, wire := tlsRoundTrip(t, client, server, payload)
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip got %q, want %q", got, payload)
	}
	if bytes.Contains(wire, payload) {
		t.Error("tlscamo leaked plaintext on the wire")
	}
}

func TestTLSCamoName(t *testing.T) {
	if got := (&TLSCamo{}).Name(); got != "tlscamo" {
		t.Errorf("Name() = %q, want %q", got, "tlscamo")
	}
}

func TestTLSCamoServerRejectsEmptyName(t *testing.T) {
	if _, err := NewTLSCamoServer(""); err == nil {
		t.Error("NewTLSCamoServer(\"\") should error")
	}
}

func TestTLSCamoClientCertPEMNil(t *testing.T) {
	if pem := NewTLSCamoClient("x", nil).CertPEM(); pem != nil {
		t.Errorf("client CertPEM() = %q, want nil", pem)
	}
}

func TestTLSCamoMalformedPinFailsClosed(t *testing.T) {
	client := NewTLSCamoClient("x", []byte("not a certificate"))
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if _, err := client.Client(left); err == nil {
		t.Fatal("malformed non-empty pin fell back to insecure TLS")
	}
}

package transport

import (
	"bytes"
	"crypto/x509"
	"io"
	"net"
	"testing"
)

// TestWSSCamoRoundTrip proves the WSS transport does verifying-TLS + a WebSocket
// upgrade end to end: a payload survives client->server->client over a real TCP
// socket (TLS needs a bidirectional socket, so net.Pipe won't do).
func TestWSSCamoRoundTrip(t *testing.T) {
	srv, err := NewWSSCamoServer("relay.test")
	if err != nil {
		t.Fatal(err)
	}
	cli := NewWSSCamoClient("relay.test")
	cli.noECH = true // self-signed test server publishes no ECH
	// Trust the server's self-signed cert (stands in for the CDN's real cert).
	leaf, err := x509.ParseCertificate(srv.cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	cli.roots = pool

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan []byte, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			done <- nil
			return
		}
		defer raw.Close()
		sc, err := srv.Server(raw)
		if err != nil {
			done <- nil
			return
		}
		buf := make([]byte, 64)
		n, err := sc.Read(buf)
		if err != nil {
			done <- nil
			return
		}
		_, _ = sc.Write(buf[:n]) // echo
		done <- append([]byte(nil), buf[:n]...)
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	cc, err := cli.Client(raw)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	payload := []byte("wireguard-over-wss-through-a-cdn")
	if _, err := cc.Write(payload); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(cc, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("echo = %q, want %q", echo, payload)
	}
	if got := <-done; !bytes.Equal(got, payload) {
		t.Fatalf("server received %q, want %q", got, payload)
	}
}

// TestWSSCamoRejectsUntrustedCert confirms the client verifies TLS: against a
// self-signed cert not in its roots (system roots), the handshake must fail —
// so WSS also defends against an on-path TLS MITM, not just DPI.
func TestWSSCamoRejectsUntrustedCert(t *testing.T) {
	srv, err := NewWSSCamoServer("relay.test")
	if err != nil {
		t.Fatal(err)
	}
	cli := NewWSSCamoClient("relay.test") // system roots → won't trust self-signed
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if raw, err := ln.Accept(); err == nil {
			_, _ = srv.Server(raw)
			raw.Close()
		}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := cli.Client(raw); err == nil {
		t.Fatal("expected TLS verification failure against an untrusted self-signed cert")
	}
}

// TestECHFromSVCB checks the ECHConfigList (SvcParam key 5) is extracted from an
// SVCB/HTTPS RDATA — priority, target ".", an alpn param, then the ech param.
func TestECHFromSVCB(t *testing.T) {
	// prio=1 | target="." | key1(alpn) len2 "h2"... | key5(ech) len4 = deadbeef
	rdata := []byte{
		0x00, 0x01, // SvcPriority
		0x00,                                   // TargetName "."
		0x00, 0x01, 0x00, 0x03, 0x02, 'h', '2', // alpn
		0x00, 0x05, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef, // ech
	}
	got := echFromSVCB(rdata)
	want := []byte{0xde, 0xad, 0xbe, 0xef}
	if !bytes.Equal(got, want) {
		t.Fatalf("echFromSVCB = %x, want %x", got, want)
	}
	// No ech param → nil.
	if echFromSVCB([]byte{0x00, 0x01, 0x00}) != nil {
		t.Fatal("expected nil when no ech param present")
	}
	// generic RDATA presentation parsing.
	if !bytes.Equal(parseGenericRDATA(`\# 3 00 01 00`), []byte{0x00, 0x01, 0x00}) {
		t.Fatal("parseGenericRDATA failed")
	}
}

package transport

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
)

// roundTrip runs a client->server exchange over an in-memory pipe using the
// given transport, returning what the server received (plaintext) and the raw
// bytes seen on the wire.
func roundTrip(t *testing.T, tr Transport, payload []byte) (received, wire []byte) {
	t.Helper()
	cRaw, sRaw := net.Pipe()

	// Tap the wire between client and server to observe obfuscated bytes.
	tap := &tapConn{Conn: sRaw}

	var wg sync.WaitGroup
	wg.Add(1)
	var serverGot []byte
	var serverErr error
	go func() {
		defer wg.Done()
		sc, err := tr.Server(tap)
		if err != nil {
			serverErr = err
			return
		}
		buf := make([]byte, len(payload))
		_, serverErr = io.ReadFull(sc, buf)
		serverGot = buf
	}()

	cc, err := tr.Client(cRaw)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := cc.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}
	wg.Wait()
	if serverErr != nil {
		t.Fatalf("server: %v", serverErr)
	}
	return serverGot, tap.Bytes()
}

func TestPlainPassthrough(t *testing.T) {
	payload := []byte("hello wireguard")
	got, wire := roundTrip(t, Plain{}, payload)
	if !bytes.Equal(got, payload) {
		t.Fatalf("plain got %q, want %q", got, payload)
	}
	if !bytes.Contains(wire, payload) {
		t.Error("plain transport should show payload verbatim on the wire")
	}
}

func TestObfsRoundTripAndObfuscation(t *testing.T) {
	secret := []byte("shared-obfs-secret")
	payload := []byte("this-is-a-wireguard-ciphertext-packet")
	got, wire := roundTrip(t, NewObfs(secret), payload)

	if !bytes.Equal(got, payload) {
		t.Fatalf("obfs round-trip got %q, want %q", got, payload)
	}
	// The payload must NOT appear in cleartext on the wire.
	if bytes.Contains(wire, payload) {
		t.Error("obfs transport leaked plaintext on the wire")
	}
}

func TestObfsWireVariesBySession(t *testing.T) {
	secret := []byte("s")
	payload := []byte("AAAAAAAAAAAAAAAA")
	_, wire1 := roundTrip(t, NewObfs(secret), payload)
	_, wire2 := roundTrip(t, NewObfs(secret), payload)
	// Random salt + padding => two sessions produce different ciphertext/length.
	if bytes.Equal(wire1, wire2) {
		t.Error("obfs sessions should differ (random salt/padding)")
	}
}

// tapConn records everything written to the underlying conn (the client->server
// direction), which is what a censor's DPI would inspect.
type tapConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (t *tapConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		t.mu.Lock()
		t.buf.Write(p[:n])
		t.mu.Unlock()
	}
	return n, err
}

func (t *tapConn) Bytes() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.buf.Bytes()...)
}

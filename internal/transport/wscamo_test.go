package transport

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
)

// wsWriteTap records everything written to the underlying conn (the
// client->server direction on the wire) so a test can inspect what a censor's DPI
// would see: the HTTP upgrade handshake followed by masked WebSocket frames.
type wsWriteTap struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *wsWriteTap) Write(p []byte) (int, error) {
	n, err := w.Conn.Write(p)
	if n > 0 {
		w.mu.Lock()
		w.buf.Write(p[:n])
		w.mu.Unlock()
	}
	return n, err
}

func (w *wsWriteTap) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

// wsHarness runs a full client->server->client exchange over a real TCP listener.
// The server, in a goroutine, accepts, completes Server(), reads len(payload)
// bytes and echoes them back. It returns what the server received and the raw
// client->server bytes observed on the wire.
func wsHarness(t *testing.T, payload []byte) (received, wire []byte) {
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
		sc, err := NewWSCamoServer().Server(raw)
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
		if _, err := sc.Write(buf); err != nil { // echo back (server->client)
			serverErr = err
		}
	}()

	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawClient.Close()

	tap := &wsWriteTap{Conn: rawClient}
	cc, err := NewWSCamoClient("cloud.example.com").Client(tap)
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
		t.Fatalf("echo got %d bytes mismatching payload", len(echo))
	}
	return serverGot, tap.Bytes()
}

func TestWSCamoRoundTripSizes(t *testing.T) {
	sizes := []int{5, 125, 200, 70000} // 7-bit, 7-bit edge, 16-bit, 64-bit forms
	for _, n := range sizes {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte('A' + (i % 26))
		}
		got, _ := wsHarness(t, payload)
		if !bytes.Equal(got, payload) {
			t.Fatalf("size %d: round-trip mismatch (got %d bytes)", n, len(got))
		}
	}
}

func TestWSCamoHandshakeLooksLikeWebSocket(t *testing.T) {
	secret := []byte("SECRET-WIREGUARD-PLAINTEXT-MARKER")
	_, wire := wsHarness(t, secret)

	// The wire must begin with an HTTP GET requesting a WebSocket upgrade.
	if !bytes.HasPrefix(wire, []byte("GET ")) {
		t.Errorf("wire did not begin with an HTTP GET, got %q", wire[:min(16, len(wire))])
	}
	if !bytes.Contains(wire, []byte("Upgrade: websocket")) {
		t.Error("handshake missing 'Upgrade: websocket' header")
	}
	if !bytes.Contains(wire, []byte("Sec-WebSocket-Key:")) {
		t.Error("handshake missing Sec-WebSocket-Key header")
	}

	// The known plaintext must NOT appear verbatim: client frames are masked.
	if bytes.Contains(wire, secret) {
		t.Error("plaintext payload appeared verbatim on the wire (frame not masked)")
	}
}

func TestWSCamoClientFramesAreMasked(t *testing.T) {
	// Drive one client->server frame and inspect the raw wire directly: after the
	// handshake, the first frame's second header byte must have the MASK bit set.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	payload := []byte("mask-me-please")
	var wg sync.WaitGroup
	wg.Add(1)
	var serverErr error
	go func() {
		defer wg.Done()
		raw, err := ln.Accept()
		if err != nil {
			serverErr = err
			return
		}
		defer raw.Close()
		sc, err := NewWSCamoServer().Server(raw)
		if err != nil {
			serverErr = err
			return
		}
		buf := make([]byte, len(payload))
		_, serverErr = io.ReadFull(sc, buf)
		if serverErr == nil && !bytes.Equal(buf, payload) {
			t.Errorf("server got %q, want %q", buf, payload)
		}
	}()

	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawClient.Close()

	tap := &wsWriteTap{Conn: rawClient}
	cc, err := NewWSCamoClient("host.example").Client(tap)
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

	wire := tap.Bytes()
	idx := bytes.Index(wire, []byte("\r\n\r\n"))
	if idx < 0 {
		t.Fatal("no handshake terminator found on the wire")
	}
	frame := wire[idx+4:]
	if len(frame) < 2 {
		t.Fatal("no frame bytes after handshake")
	}
	if frame[0] != (0x80 | wsOpcodeBinary) {
		t.Errorf("first frame byte = 0x%x, want FIN|BINARY 0x82", frame[0])
	}
	if frame[1]&0x80 == 0 {
		t.Error("client frame MASK bit not set (client frames MUST be masked)")
	}
}

func TestWSCamoName(t *testing.T) {
	if got := NewWSCamoServer().Name(); got != "wscamo" {
		t.Errorf("Name() = %q, want %q", got, "wscamo")
	}
}

func TestWSCamoServerRejectsNonUpgrade(t *testing.T) {
	cRaw, sRaw := net.Pipe()
	defer cRaw.Close()
	defer sRaw.Close()

	go func() {
		io.WriteString(cRaw, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	}()
	if _, err := NewWSCamoServer().Server(sRaw); err == nil {
		t.Error("Server should reject a request that is not a websocket upgrade")
	}
}

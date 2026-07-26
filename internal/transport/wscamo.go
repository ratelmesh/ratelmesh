package transport

// WSCamo camouflages the link as ordinary WebSocket traffic (DESIGN.md §8). To a
// censor's DPI the flow opens with a genuine HTTP/1.1 Upgrade handshake — a GET
// carrying Upgrade: websocket, Connection: Upgrade and a Sec-WebSocket-Key — and
// the server answers with a real "101 Switching Protocols" plus the matching
// Sec-WebSocket-Accept. Everything after that is wrapped in RFC 6455 BINARY
// frames, exactly as a browser's WebSocket would carry application data. The
// WireGuard ciphertext rides inside those frames, so no WireGuard byte signature
// ever reaches the wire and the connection is indistinguishable from a long-lived
// WebSocket (chat, live feed, etc.).
//
// Per RFC 6455 the dialing (client) side MUST mask every frame with a fresh
// 4-byte key and the accepting (server) side MUST NOT mask; wsConn enforces this
// and unmasks on read. WSCamo is the dependency-free cousin of the CDN/WebSocket
// front used to smuggle proxy traffic past DPI that allows plain HTTP but blocks
// unknown protocols.
//
// Both sides must agree out of band on serverName: it becomes the Host header so
// the request looks like it targets a real site of that name.

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

// wsCamoName identifies the transport.
const wsCamoName = "wscamo"

// wsMagicGUID is the RFC 6455 handshake constant appended to Sec-WebSocket-Key
// before hashing to produce Sec-WebSocket-Accept.
const wsMagicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// wsCamoPath is a plausible request path a real WebSocket endpoint might serve.
const wsCamoPath = "/chat"

// wsMaxFrameSize caps a single WebSocket frame's payload so a forged 64-bit
// length cannot trigger a huge allocation (memory DoS). WireGuard datagrams are
// tiny; 1 MiB is generous.
const wsMaxFrameSize = 1 << 20

const (
	wsMaxHeaderLineBytes          = 4096
	wsMaxHeaderBytes              = 16 << 10
	wsMaxHeaderCount              = 64
	wsMaxConsecutiveControlFrames = 32
)

var (
	// errFrameTooLarge is returned when a frame's declared length exceeds the cap.
	errFrameTooLarge      = errors.New("wscamo: frame exceeds maximum size")
	errInvalidFrame       = errors.New("wscamo: invalid WebSocket frame")
	errHTTPHeaderTooLarge = errors.New("wscamo: HTTP upgrade headers exceed limit")
)

// WebSocket opcodes (RFC 6455 §5.2) used by this transport.
const (
	wsOpcodeContinuation = 0x0
	wsOpcodeText         = 0x1
	wsOpcodeBinary       = 0x2
	wsOpcodeClose        = 0x8
	wsOpcodePing         = 0x9
	wsOpcodePong         = 0xA
)

// WSCamo wraps a raw connection so it looks like WebSocket traffic on the wire.
// A single value is used per role: build the dialing side with NewWSCamoClient
// and the accepting side with NewWSCamoServer.
type WSCamo struct {
	serverName string // client side: Host header target; unused server side
	isClient   bool
}

// NewWSCamoClient builds the dialing side. serverName is sent as the Host header
// so the handshake appears to target a real site of that name.
func NewWSCamoClient(serverName string) *WSCamo {
	return &WSCamo{serverName: serverName, isClient: true}
}

// NewWSCamoServer builds the accepting side, which validates the incoming
// upgrade request and completes the WebSocket handshake.
func NewWSCamoServer() *WSCamo {
	return &WSCamo{isClient: false}
}

// Name identifies the transport.
func (*WSCamo) Name() string { return wsCamoName }

// Client performs the client-side WebSocket upgrade handshake over raw and
// returns a conn that frames all subsequent bytes as masked BINARY frames.
func (t *WSCamo) Client(raw net.Conn) (net.Conn, error) {
	keyBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, keyBytes); err != nil {
		return nil, fmt.Errorf("wscamo: client key: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	host := t.serverName
	if host == "" {
		host = "localhost"
	}
	if strings.ContainsAny(host, "\r\n") {
		return nil, errors.New("wscamo: invalid server name")
	}
	req := "GET " + wsCamoPath + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	if _, err := io.WriteString(raw, req); err != nil {
		return nil, fmt.Errorf("wscamo: client write handshake: %w", err)
	}

	// bufio.Reader may buffer bytes past the handshake (the first frames); it is
	// handed to the wsConn so nothing is lost.
	br := bufio.NewReaderSize(raw, wsMaxHeaderLineBytes+1)
	statusLine, headers, err := readHTTPMessage(br)
	if err != nil {
		return nil, fmt.Errorf("wscamo: client read handshake: %w", err)
	}
	// Expect "HTTP/1.1 101 Switching Protocols".
	fields := strings.Fields(statusLine)
	if len(fields) < 2 || fields[0] != "HTTP/1.1" || fields[1] != "101" {
		return nil, errors.New("wscamo: unexpected handshake status")
	}
	if !strings.EqualFold(headers["upgrade"], "websocket") {
		return nil, errors.New("wscamo: server did not confirm websocket upgrade")
	}
	if !headerHasToken(headers["connection"], "upgrade") {
		return nil, errors.New("wscamo: server did not confirm Connection: Upgrade")
	}
	want := computeAccept(key)
	if headers["sec-websocket-accept"] != want {
		return nil, errors.New("wscamo: bad Sec-WebSocket-Accept")
	}

	return newWSConn(raw, br, true), nil
}

// Server reads and validates the client's upgrade request, replies 101 Switching
// Protocols, and returns a conn that de-frames masked client frames and writes
// unmasked BINARY frames back.
func (t *WSCamo) Server(raw net.Conn) (net.Conn, error) {
	br := bufio.NewReaderSize(raw, wsMaxHeaderLineBytes+1)
	requestLine, headers, err := readHTTPMessage(br)
	if err != nil {
		return nil, fmt.Errorf("wscamo: server read handshake: %w", err)
	}
	// Expect "GET <path> HTTP/1.1".
	fields := strings.Fields(requestLine)
	if len(fields) != 3 || fields[0] != "GET" || fields[1] != wsCamoPath || fields[2] != "HTTP/1.1" {
		return nil, errors.New("wscamo: invalid upgrade request line")
	}
	if headers["host"] == "" {
		return nil, errors.New("wscamo: request missing Host")
	}
	if headers["origin"] != "" {
		return nil, errors.New("wscamo: browser-origin WebSocket requests are not accepted")
	}
	if !strings.EqualFold(headers["upgrade"], "websocket") {
		return nil, errors.New("wscamo: request is not a websocket upgrade")
	}
	if !headerHasToken(headers["connection"], "upgrade") {
		return nil, errors.New("wscamo: request missing Connection: Upgrade")
	}
	key := headers["sec-websocket-key"]
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decodedKey) != 16 {
		return nil, errors.New("wscamo: invalid Sec-WebSocket-Key")
	}
	if headers["sec-websocket-version"] != "13" {
		return nil, errors.New("wscamo: unsupported WebSocket version")
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + computeAccept(key) + "\r\n" +
		"\r\n"
	if _, err := io.WriteString(raw, resp); err != nil {
		return nil, fmt.Errorf("wscamo: server write handshake: %w", err)
	}

	return newWSConn(raw, br, false), nil
}

// computeAccept derives the Sec-WebSocket-Accept response value from the client's
// Sec-WebSocket-Key per RFC 6455 §4.2.2: base64(sha1(key + magic GUID)).
func computeAccept(key string) string {
	h := sha1.New()
	io.WriteString(h, key)
	io.WriteString(h, wsMagicGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// readHTTPMessage reads the first line (request or status line) and the header
// block terminated by a blank line from br, returning the first line and a map
// of lower-cased header names to values. Bytes buffered by br past the blank line
// (i.e. the first WebSocket frames) remain available to later reads.
func readHTTPMessage(br *bufio.Reader) (firstLine string, headers map[string]string, err error) {
	firstLine, err = readLine(br)
	if err != nil {
		return "", nil, err
	}
	total := len(firstLine) + 2
	headers = make(map[string]string)
	for {
		line, lerr := readLine(br)
		if lerr != nil {
			return "", nil, lerr
		}
		total += len(line) + 2
		if total > wsMaxHeaderBytes {
			return "", nil, errHTTPHeaderTooLarge
		}
		if line == "" {
			break
		}
		if len(headers) >= wsMaxHeaderCount {
			return "", nil, errHTTPHeaderTooLarge
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return "", nil, errors.New("wscamo: malformed HTTP header")
		}
		name := strings.ToLower(strings.TrimSpace(line[:colon]))
		value := strings.TrimSpace(line[colon+1:])
		if name == "" {
			return "", nil, errors.New("wscamo: malformed HTTP header name")
		}
		if _, exists := headers[name]; exists {
			return "", nil, errors.New("wscamo: duplicate HTTP header")
		}
		headers[name] = value
	}
	return firstLine, headers, nil
}

func headerHasToken(value, want string) bool {
	for _, token := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(token), want) {
			return true
		}
	}
	return false
}

// readLine reads a bounded CRLF- (or LF-) terminated line and returns it without
// the terminator. ReadSlice deliberately fails at the fixed reader boundary
// rather than allocating until an attacker eventually sends a newline.
func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > wsMaxHeaderLineBytes {
		return "", errHTTPHeaderTooLarge
	}
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

// wsConn frames outbound writes as RFC 6455 BINARY frames and de-frames inbound
// reads, buffering any partial frame payload across Read calls. When isClient is
// true it masks every outbound frame with a fresh key and expects unmasked
// inbound frames; the server side does the reverse.
type wsConn struct {
	net.Conn               // underlying raw conn (for Write and deadline passthrough)
	br       *bufio.Reader // buffered reader holding any bytes past the handshake
	isClient bool

	wmu     sync.Mutex // serializes writes
	rmu     sync.Mutex // serializes reads / protects readBuf
	readBuf []byte     // leftover unmasked payload from a partially consumed frame
}

func newWSConn(raw net.Conn, br *bufio.Reader, isClient bool) *wsConn {
	return &wsConn{Conn: raw, br: br, isClient: isClient}
}

// Read returns de-framed tunnel bytes, unmasking client frames on the server
// side. Frame payloads are buffered so a caller's small buffer can drain a large
// frame across several Reads.
func (c *wsConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	controlFrames := 0
	for len(c.readBuf) == 0 {
		payload, opcode, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		switch opcode {
		case wsOpcodeBinary:
			c.readBuf = payload
		case wsOpcodeClose:
			return 0, io.EOF
		case wsOpcodePing, wsOpcodePong:
			// Control frames carry no tunnel data; ignore and read the next one.
			controlFrames++
			if controlFrames > wsMaxConsecutiveControlFrames {
				return 0, errInvalidFrame
			}
			continue
		default:
			return 0, fmt.Errorf("wscamo: unknown opcode 0x%x", opcode)
		}
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// readFrame reads one complete WebSocket frame from br, returning its unmasked
// payload and opcode. It supports the 7-bit, 16-bit (126) and 64-bit (127)
// payload length forms.
func (c *wsConn) readFrame() ([]byte, byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return nil, 0, err
	}
	opcode := hdr[0] & 0x0f
	fin := hdr[0]&0x80 != 0
	if hdr[0]&0x70 != 0 || !fin {
		return nil, 0, errInvalidFrame
	}
	masked := hdr[1]&0x80 != 0
	if masked != !c.isClient {
		return nil, 0, errInvalidFrame
	}
	length := uint64(hdr[1] & 0x7f)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return nil, 0, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return nil, 0, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}

	// Cap the frame size before allocating, so a malicious peer cannot trigger a
	// huge allocation with a forged 64-bit length (memory DoS).
	if length > wsMaxFrameSize {
		return nil, 0, errFrameTooLarge
	}
	if opcode >= wsOpcodeClose && length > 125 {
		return nil, 0, errInvalidFrame
	}
	switch opcode {
	case wsOpcodeBinary, wsOpcodeClose, wsOpcodePing, wsOpcodePong:
	default:
		return nil, 0, errInvalidFrame
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(c.br, maskKey[:]); err != nil {
			return nil, 0, err
		}
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return nil, 0, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i&3]
		}
	}
	return payload, opcode, nil
}

// Write frames p as a single BINARY frame and sends it, masking on the client
// side per RFC 6455.
func (c *wsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	frame, err := c.buildFrame(p)
	if err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

// buildFrame constructs a single FIN BINARY frame carrying p, choosing the
// 7-/16-/64-bit length form and masking the payload when isClient is true.
func (c *wsConn) buildFrame(p []byte) ([]byte, error) {
	n := uint64(len(p))
	if n > wsMaxFrameSize {
		return nil, errFrameTooLarge
	}

	// First byte: FIN | opcode.
	header := []byte{0x80 | wsOpcodeBinary}

	var lenField byte
	var ext []byte
	switch {
	case n < 126:
		lenField = byte(n)
	case n <= 0xFFFF:
		lenField = 126
		ext = make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(n))
	default:
		lenField = 127
		ext = make([]byte, 8)
		binary.BigEndian.PutUint64(ext, n)
	}

	if c.isClient {
		lenField |= 0x80 // set MASK bit
	}
	header = append(header, lenField)
	header = append(header, ext...)

	if !c.isClient {
		return append(header, p...), nil
	}

	// Client: append a fresh 4-byte mask key and the masked payload.
	var maskKey [4]byte
	if _, err := io.ReadFull(rand.Reader, maskKey[:]); err != nil {
		return nil, fmt.Errorf("wscamo: mask key: %w", err)
	}
	frame := make([]byte, 0, len(header)+4+len(p))
	frame = append(frame, header...)
	frame = append(frame, maskKey[:]...)
	for i := 0; i < len(p); i++ {
		frame = append(frame, p[i]^maskKey[i&3])
	}
	return frame, nil
}

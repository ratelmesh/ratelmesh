package transport

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func validUpgradeRequest(extra string) string {
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	return "GET /chat HTTP/1.1\r\n" +
		"Host: relay.example\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: keep-alive, Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		extra + "\r\n"
}

func serverHandshakeError(t *testing.T, request string) error {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_ = client.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = io.WriteString(client, request)
	}()
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	_, err := NewWSCamoServer().Server(server)
	return err
}

func TestWSCamoServerRejectsCrossSiteAndAmbiguousUpgrades(t *testing.T) {
	tests := map[string]string{
		"wrong path":        strings.Replace(validUpgradeRequest(""), "/chat", "/proxy", 1),
		"browser origin":    validUpgradeRequest("Origin: https://evil.example\r\n"),
		"duplicate header":  validUpgradeRequest("Upgrade: h2c\r\n"),
		"wrong version":     strings.Replace(validUpgradeRequest(""), "Version: 13", "Version: 12", 1),
		"invalid key":       strings.Replace(validUpgradeRequest(""), base64.StdEncoding.EncodeToString(make([]byte, 16)), "not-base64", 1),
		"substring upgrade": strings.Replace(validUpgradeRequest(""), "keep-alive, Upgrade", "keep-alive, notupgrade", 1),
	}
	for name, request := range tests {
		t.Run(name, func(t *testing.T) {
			if err := serverHandshakeError(t, request); err == nil {
				t.Fatal("ambiguous/cross-site WebSocket upgrade was accepted")
			}
		})
	}
}

func TestWSCamoHandshakeHeadersAreBounded(t *testing.T) {
	request := validUpgradeRequest("X-Oversized: " + strings.Repeat("a", wsMaxHeaderLineBytes) + "\r\n")
	if err := serverHandshakeError(t, request); !errors.Is(err, errHTTPHeaderTooLarge) {
		t.Fatalf("oversized header error=%v, want errHTTPHeaderTooLarge", err)
	}
}

func TestWSCamoEnforcesFrameMaskDirection(t *testing.T) {
	tests := []struct {
		name     string
		isClient bool
		frame    []byte
	}{
		{
			name:     "server rejects unmasked client frame",
			isClient: false,
			frame:    []byte{0x82, 0x01, 'x'},
		},
		{
			name:     "client rejects masked server frame",
			isClient: true,
			frame:    []byte{0x82, 0x81, 1, 2, 3, 4, 'x' ^ 1},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader, writer := net.Pipe()
			defer reader.Close()
			defer writer.Close()
			conn := newWSConn(reader, bufio.NewReader(reader), test.isClient)
			go func() {
				_ = writer.SetWriteDeadline(time.Now().Add(time.Second))
				_, _ = writer.Write(test.frame)
			}()
			_ = reader.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, errInvalidFrame) {
				t.Fatalf("mask-direction error=%v, want errInvalidFrame", err)
			}
		})
	}
}

func TestWSCamoRejectsOversizedWrite(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn := newWSConn(left, bufio.NewReader(left), true)
	if _, err := conn.Write(make([]byte, wsMaxFrameSize+1)); !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("oversized write error=%v, want errFrameTooLarge", err)
	}
}

func TestWSCamoCapsControlFramesWithoutTunnelData(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	defer writer.Close()
	conn := newWSConn(reader, bufio.NewReader(reader), true)
	go func() {
		_ = writer.SetWriteDeadline(time.Now().Add(time.Second))
		for range wsMaxConsecutiveControlFrames + 1 {
			_, _ = writer.Write([]byte{0x89, 0x00}) // FIN|PING, unmasked server frame
		}
	}()
	_ = reader.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, errInvalidFrame) {
		t.Fatalf("control-frame flood error=%v, want errInvalidFrame", err)
	}
}

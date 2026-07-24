package transport

import (
	"bufio"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// TestWSCamoRejectsOversizedFrame ensures a forged 64-bit length beyond the cap
// is rejected before any allocation (memory-DoS guard).
func TestWSCamoRejectsOversizedFrame(t *testing.T) {
	cSide, sSide := net.Pipe()
	defer cSide.Close()
	defer sSide.Close()

	// Client-side wsConn reads server frames (unmasked).
	wc := newWSConn(cSide, bufio.NewReader(cSide), true)

	// Craft a server->client BINARY frame header claiming a ~1 TiB payload.
	go func() {
		hdr := []byte{0x82, 0x7f} // FIN|binary, mask=0 + 127 (64-bit length follows)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], 1<<40)
		_ = sSide.SetWriteDeadline(time.Now().Add(time.Second))
		sSide.Write(append(hdr, ext[:]...))
	}()

	_ = wc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	_, err := wc.Read(buf)
	if !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("Read of oversized frame = %v, want errFrameTooLarge", err)
	}
}

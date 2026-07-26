// Package relay implements the RatelMesh relay (DERP-style), the fallback path
// when two peers cannot establish a direct WireGuard connection (DESIGN.md §3.2).
// The relay only ever sees WireGuard ciphertext keyed by peer public key; it
// cannot decrypt traffic.
//
// Wire format (length-prefixed frames):
//
//	[4 bytes big-endian length N][1 byte frame type][N-1 bytes payload]
//
// In production these frames run inside a TLS:443 connection so they traverse
// restrictive firewalls (DESIGN.md §3.2); the framing here is transport-agnostic
// and is exercised in tests over plain TCP.
package relay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/ratelmesh/ratelmesh/internal/types"
)

// FrameType identifies a relay frame.
type FrameType byte

const (
	// FrameBind (client→relay): payload is the client's 32-byte public key. The
	// relay records the connection under that key.
	FrameBind FrameType = 1
	// FrameForward (client→relay): payload is dstKey(32) || ciphertext. The relay
	// delivers it to the connection bound to dstKey.
	FrameForward FrameType = 2
	// FrameRecv (relay→client): payload is srcKey(32) || ciphertext.
	FrameRecv FrameType = 3
	// FrameBindOK (relay→client): empty payload, acknowledges a successful bind.
	FrameBindOK FrameType = 4
	// FrameRelayHello (relay→relay): first frame on a sibling link, empty payload,
	// marks the connection as another relay rather than a client.
	FrameRelayHello FrameType = 5
	// FrameRelayDeliver (relay→relay): payload is dstKey(32) || srcKey(32) ||
	// ciphertext. A relay that receives a client frame for a peer it does not
	// hold broadcasts this to its siblings; the sibling holding dst delivers it.
	FrameRelayDeliver FrameType = 6
	// FrameChallenge (relay→client): payload is ephemeralPub(32) || nonce(16),
	// the proof-of-possession challenge issued after a bind (security review §4).
	FrameChallenge FrameType = 7
	// FrameProof (client→relay): payload is the 32-byte HMAC proof.
	FrameProof FrameType = 8
)

const (
	keyLen       = 32
	maxFrameSize = 1 << 20 // 1 MiB ceiling guards against malicious length prefixes
)

var (
	errFrameTooLarge = errors.New("relay: frame exceeds maximum size")
	errShortPayload  = errors.New("relay: payload shorter than required")
)

// writeFrame encodes one frame to w.
func writeFrame(w io.Writer, t FrameType, payload []byte) error {
	n := len(payload) + 1
	if n > maxFrameSize {
		return errFrameTooLarge
	}
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(n))
	hdr[4] = byte(t)
	if err := writeAll(w, hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if err := writeAll(w, payload); err != nil {
			return err
		}
	}
	return nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

// readFrame decodes one frame from r.
func readFrame(r io.Reader) (FrameType, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n < 1 || n > maxFrameSize {
		return 0, nil, errFrameTooLarge
	}
	payload := make([]byte, n-1)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return FrameType(hdr[4]), payload, nil
}

// encodeForward builds a FrameForward payload: dstKey || data.
func encodeForward(dst types.Key, data []byte) []byte {
	buf := make([]byte, keyLen+len(data))
	copy(buf, dst[:])
	copy(buf[keyLen:], data)
	return buf
}

// decodeKeyed splits a keyed payload (FrameForward/FrameRecv) into key + data.
func decodeKeyed(payload []byte) (types.Key, []byte, error) {
	if len(payload) < keyLen {
		return types.Key{}, nil, fmt.Errorf("%w: got %d, want >=%d", errShortPayload, len(payload), keyLen)
	}
	var k types.Key
	copy(k[:], payload[:keyLen])
	return k, payload[keyLen:], nil
}

// encodeRelayDeliver builds a FrameRelayDeliver payload: dst || src || data.
func encodeRelayDeliver(dst, src types.Key, data []byte) []byte {
	buf := make([]byte, keyLen*2+len(data))
	copy(buf, dst[:])
	copy(buf[keyLen:], src[:])
	copy(buf[keyLen*2:], data)
	return buf
}

// decodeRelayDeliver splits a FrameRelayDeliver payload into dst, src, data.
func decodeRelayDeliver(payload []byte) (dst, src types.Key, data []byte, err error) {
	if len(payload) < keyLen*2 {
		return dst, src, nil, fmt.Errorf("%w: got %d, want >=%d", errShortPayload, len(payload), keyLen*2)
	}
	copy(dst[:], payload[:keyLen])
	copy(src[:], payload[keyLen:keyLen*2])
	return dst, src, payload[keyLen*2:], nil
}

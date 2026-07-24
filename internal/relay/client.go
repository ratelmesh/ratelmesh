package relay

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/transport"
	"github.com/ratelmesh/ratelmesh/internal/types"
)

// Client is a peer's connection to a relay. It binds under the peer's public
// key and offers Send (to a dst key) plus a receive callback. magicsock uses
// this as the relay path and races it against direct connections (DESIGN.md §3.2).
type Client struct {
	self   types.Key
	nc     net.Conn
	remote net.Addr // resolved TCP peer address (for the kill-switch TCP allow)

	mu     sync.Mutex
	closed bool
}

// RemoteAddr returns the relay's resolved network address (post-DNS), so callers
// (e.g. the kill switch) get an IP even when the relay was dialed by hostname.
func (c *Client) RemoteAddr() net.Addr { return c.remote }

// RecvFunc is invoked for each frame delivered to this client: the source peer
// key and the ciphertext payload.
type RecvFunc func(src types.Key, data []byte)

// Dial connects to a relay with no obfuscation (Plain transport).
// Dial connects with no obfuscation. priv is the node's PRIVATE key: the relay
// requires a proof of possession before binding (security review §4).
func Dial(ctx context.Context, addr string, priv types.Key) (*Client, error) {
	return DialWithTransport(ctx, addr, priv, transport.Plain{})
}

// DialWithTransport connects to a relay at addr, wrapping the link in tr, and
// binds under priv's public key — proving possession of priv via the relay's
// X25519 challenge. It blocks until the relay acknowledges the bind.
func DialWithTransport(ctx context.Context, addr string, priv types.Key, tr transport.Transport) (*Client, error) {
	return DialWithAdmission(ctx, addr, priv, tr, nil)
}

// DialWithAdmission authenticates both node-key possession and fleet membership.
func DialWithAdmission(ctx context.Context, addr string, priv types.Key, tr transport.Transport, clientSecret []byte) (*Client, error) {
	if tr == nil {
		tr = transport.Plain{}
	}
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	// Bound the WHOLE handshake — the camouflage transport's own handshake (TLS
	// negotiation, WebSocket upgrade) happens inside tr.Client, so the deadline
	// must be set on the raw conn BEFORE wrapping, not after (security review). A
	// relay that accepts TCP but never speaks the protocol must not hang us.
	deadline := time.Now().Add(15 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = raw.SetDeadline(deadline)
	remote := raw.RemoteAddr() // resolved IP:port, captured before any wrapping
	nc, err := tr.Client(raw)
	if err != nil {
		raw.Close()
		return nil, err
	}
	pub := priv.Public()
	c := &Client{self: pub, nc: nc, remote: remote}
	if err := writeFrame(nc, FrameBind, pub[:]); err != nil {
		nc.Close()
		return nil, err
	}
	// Answer the proof-of-possession challenge.
	ct, chal, err := readFrame(nc)
	if err != nil {
		nc.Close()
		return nil, err
	}
	if ct != FrameChallenge || len(chal) != 32+nonceLen {
		nc.Close()
		return nil, fmt.Errorf("relay: expected challenge, got %d", ct)
	}
	var ephPub [32]byte
	copy(ephPub[:], chal[:32])
	proof, err := proofFor(priv, ephPub, chal[32:])
	if err != nil {
		nc.Close()
		return nil, err
	}
	if len(clientSecret) > 0 {
		proof = append(proof, admissionProof(clientSecret, pub, chal[32:])...)
	}
	if err := writeFrame(nc, FrameProof, proof); err != nil {
		nc.Close()
		return nil, err
	}
	t, _, err := readFrame(nc)
	if err != nil {
		nc.Close()
		return nil, err
	}
	if t != FrameBindOK {
		nc.Close()
		return nil, fmt.Errorf("relay: unexpected bind reply %d", t)
	}
	_ = nc.SetDeadline(time.Time{}) // clear: steady-state Receive must not time out
	return c, nil
}

// Send relays data to the peer bound as dst.
func (c *Client) Send(dst types.Key, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	return writeFrame(c.nc, FrameForward, encodeForward(dst, data))
}

// Receive loops reading delivered frames, invoking fn for each, until the
// connection closes or ctx is cancelled.
func (c *Client) Receive(ctx context.Context, fn RecvFunc) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-done:
		}
	}()
	defer close(done)
	for {
		t, payload, err := readFrame(c.nc)
		if err != nil {
			return err
		}
		if t != FrameRecv {
			continue
		}
		src, data, err := decodeKeyed(payload)
		if err != nil {
			continue
		}
		fn(src, data)
	}
}

// Close tears down the relay connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.nc.Close()
}

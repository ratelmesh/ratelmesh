package transport

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/chacha20"
)

// Obfs is a "look-like-nothing" obfuscator. After a short handshake it XORs the
// stream with a per-session ChaCha20 keystream, so the bytes on the wire carry
// no fixed header or protocol signature — defeating signature-based DPI. It is
// NOT a substitute for REALITY against active probing (an attacker who knows the
// pre-shared secret can still detect it); it is the dependency-free baseline of
// the pluggable transport layer (DESIGN.md §8.2).
//
// Handshake (client -> server), all after the salt is keystream-encrypted:
//
//	[16-byte random salt (cleartext)]
//	[1-byte padding length P][P random padding bytes]   // varies flow size
//
// Both sides derive two direction-specific keys from secret+salt, so the two
// directions never share a keystream.
type Obfs struct {
	secret []byte
}

// NewObfs builds an obfuscating transport keyed by a pre-shared secret.
func NewObfs(secret []byte) *Obfs { return &Obfs{secret: secret} }

func (*Obfs) Name() string { return "obfs" }

const (
	obfsSaltLen   = 16
	obfsMaxPad    = 255
	chachaKeyLen  = 32
	chachaNonce12 = 12
)

func (o *Obfs) deriveKeys(salt []byte) (c2s, s2c [chachaKeyLen]byte) {
	h := sha256.New()
	h.Write([]byte("ratelmesh-obfs-c2s"))
	h.Write(o.secret)
	h.Write(salt)
	copy(c2s[:], h.Sum(nil))
	h.Reset()
	h.Write([]byte("ratelmesh-obfs-s2c"))
	h.Write(o.secret)
	h.Write(salt)
	copy(s2c[:], h.Sum(nil))
	return
}

// Client handshakes as the dialer and returns an obfuscated conn.
func (o *Obfs) Client(raw net.Conn) (net.Conn, error) {
	salt := make([]byte, obfsSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := raw.Write(salt); err != nil {
		return nil, err
	}
	c2s, s2c := o.deriveKeys(salt)
	oc, err := newObfsConn(raw, c2s, s2c) // client writes with c2s, reads with s2c
	if err != nil {
		return nil, err
	}
	// Send randomized padding under the keystream to vary the flow's byte counts.
	if err := oc.writePadding(); err != nil {
		return nil, err
	}
	return oc, nil
}

// Server handshakes as the accepter and returns a de-obfuscated conn.
func (o *Obfs) Server(raw net.Conn) (net.Conn, error) {
	salt := make([]byte, obfsSaltLen)
	if _, err := io.ReadFull(raw, salt); err != nil {
		return nil, err
	}
	c2s, s2c := o.deriveKeys(salt)
	oc, err := newObfsConn(raw, s2c, c2s) // server writes with s2c, reads with c2s
	if err != nil {
		return nil, err
	}
	if err := oc.readPadding(); err != nil {
		return nil, err
	}
	return oc, nil
}

// obfsConn XORs reads and writes with independent ChaCha20 keystreams.
type obfsConn struct {
	net.Conn
	enc *chacha20.Cipher // write keystream
	dec *chacha20.Cipher // read keystream
}

func newObfsConn(raw net.Conn, writeKey, readKey [chachaKeyLen]byte) (*obfsConn, error) {
	nonce := make([]byte, chachaNonce12) // per-session keys => a fixed nonce is safe
	enc, err := chacha20.NewUnauthenticatedCipher(writeKey[:], nonce)
	if err != nil {
		return nil, err
	}
	dec, err := chacha20.NewUnauthenticatedCipher(readKey[:], nonce)
	if err != nil {
		return nil, err
	}
	return &obfsConn{Conn: raw, enc: enc, dec: dec}, nil
}

func (c *obfsConn) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	c.enc.XORKeyStream(buf, p)
	return c.Conn.Write(buf)
}

func (c *obfsConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.dec.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

// writePadding emits P (0..255) random padding bytes, framed by a length byte,
// all under the keystream. The receiver discards them.
func (c *obfsConn) writePadding() error {
	var lb [1]byte
	if _, err := rand.Read(lb[:]); err != nil {
		return err
	}
	pad := make([]byte, int(lb[0]))
	if _, err := rand.Read(pad); err != nil {
		return err
	}
	if _, err := c.Write(lb[:]); err != nil {
		return err
	}
	if len(pad) > 0 {
		if _, err := c.Write(pad); err != nil {
			return err
		}
	}
	return nil
}

func (c *obfsConn) readPadding() error {
	var lb [1]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return err
	}
	if lb[0] == 0 {
		return nil
	}
	if _, err := io.ReadFull(c, make([]byte, int(lb[0]))); err != nil {
		return fmt.Errorf("obfs: read padding: %w", err)
	}
	return nil
}

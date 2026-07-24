// Package magicsock handles path discovery and selection for peer connections
// (DESIGN.md §3.2): it learns each device's public endpoint via STUN, and for
// every peer maintains a path that starts on the relay and upgrades to a direct
// WireGuard connection once hole-punching succeeds.
package magicsock

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
)

// Minimal RFC 5389 STUN implementation, enough to discover our public
// ip:port via a Binding request/response (the reflexive candidate).

const (
	stunMagicCookie      = 0x2112A442
	stunBindingRequest   = 0x0001
	stunBindingSuccess   = 0x0101
	attrXORMappedAddress = 0x0020
	stunHeaderLen        = 20
)

// TxID is a STUN transaction ID.
type TxID [12]byte

// NewTxID returns a random transaction ID.
func NewTxID() (TxID, error) {
	var t TxID
	_, err := rand.Read(t[:])
	return t, err
}

// EncodeBindingRequest builds a STUN Binding request with the given tx ID.
func EncodeBindingRequest(tx TxID) []byte {
	buf := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(buf[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(buf[2:4], 0) // message length: no attributes
	binary.BigEndian.PutUint32(buf[4:8], stunMagicCookie)
	copy(buf[8:20], tx[:])
	return buf
}

var errNotSTUN = errors.New("magicsock: not a STUN success response")

// ParseBindingResponse extracts the XOR-MAPPED-ADDRESS from a Binding success
// response, returning the reflexive (public) address of the sender.
func ParseBindingResponse(buf []byte, tx TxID) (netip.AddrPort, error) {
	if len(buf) < stunHeaderLen {
		return netip.AddrPort{}, errNotSTUN
	}
	if binary.BigEndian.Uint16(buf[0:2]) != stunBindingSuccess {
		return netip.AddrPort{}, errNotSTUN
	}
	if binary.BigEndian.Uint32(buf[4:8]) != stunMagicCookie {
		return netip.AddrPort{}, errNotSTUN
	}
	var gotTx TxID
	copy(gotTx[:], buf[8:20])
	if gotTx != tx {
		return netip.AddrPort{}, errors.New("magicsock: STUN transaction ID mismatch")
	}

	attrs := buf[stunHeaderLen:]
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:2])
		alen := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+alen > len(attrs) {
			break
		}
		val := attrs[4 : 4+alen]
		if typ == attrXORMappedAddress {
			return decodeXORMappedAddress(val, gotTx)
		}
		// Attributes are padded to 4-byte boundaries.
		adv := 4 + alen
		if pad := alen % 4; pad != 0 {
			adv += 4 - pad
		}
		attrs = attrs[adv:]
	}
	return netip.AddrPort{}, errors.New("magicsock: no XOR-MAPPED-ADDRESS in response")
}

func decodeXORMappedAddress(val []byte, tx TxID) (netip.AddrPort, error) {
	if len(val) < 8 {
		return netip.AddrPort{}, errNotSTUN
	}
	family := val[1]
	port := binary.BigEndian.Uint16(val[2:4]) ^ (stunMagicCookie >> 16)

	switch family {
	case 0x01: // IPv4
		var a4 [4]byte
		cookie := make([]byte, 4)
		binary.BigEndian.PutUint32(cookie, stunMagicCookie)
		for i := 0; i < 4; i++ {
			a4[i] = val[4+i] ^ cookie[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom4(a4), port), nil
	case 0x02: // IPv6
		if len(val) < 20 {
			return netip.AddrPort{}, errNotSTUN
		}
		var a16 [16]byte
		key := make([]byte, 16)
		binary.BigEndian.PutUint32(key[0:4], stunMagicCookie)
		copy(key[4:], tx[:])
		for i := 0; i < 16; i++ {
			a16[i] = val[4+i] ^ key[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom16(a16), port), nil
	default:
		return netip.AddrPort{}, errors.New("magicsock: unknown address family")
	}
}

// EncodeBindingResponse builds a Binding success response echoing the sender's
// address as XOR-MAPPED-ADDRESS. Used by the built-in STUN server.
func EncodeBindingResponse(tx TxID, from netip.AddrPort) []byte {
	addr := from.Addr()
	var attrVal []byte
	if addr.Is4() {
		attrVal = make([]byte, 8)
		attrVal[1] = 0x01
		binary.BigEndian.PutUint16(attrVal[2:4], from.Port()^(stunMagicCookie>>16))
		cookie := make([]byte, 4)
		binary.BigEndian.PutUint32(cookie, stunMagicCookie)
		a4 := addr.As4()
		for i := 0; i < 4; i++ {
			attrVal[4+i] = a4[i] ^ cookie[i]
		}
	} else {
		attrVal = make([]byte, 20)
		attrVal[1] = 0x02
		binary.BigEndian.PutUint16(attrVal[2:4], from.Port()^(stunMagicCookie>>16))
		key := make([]byte, 16)
		binary.BigEndian.PutUint32(key[0:4], stunMagicCookie)
		copy(key[4:], tx[:])
		a16 := addr.As16()
		for i := 0; i < 16; i++ {
			attrVal[4+i] = a16[i] ^ key[i]
		}
	}

	msg := make([]byte, stunHeaderLen+4+len(attrVal))
	binary.BigEndian.PutUint16(msg[0:2], stunBindingSuccess)
	binary.BigEndian.PutUint16(msg[2:4], uint16(4+len(attrVal)))
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], tx[:])
	binary.BigEndian.PutUint16(msg[20:22], attrXORMappedAddress)
	binary.BigEndian.PutUint16(msg[22:24], uint16(len(attrVal)))
	copy(msg[24:], attrVal)
	return msg
}

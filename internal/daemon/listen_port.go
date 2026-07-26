package daemon

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/ratelmesh/ratelmesh/internal/types"
)

// Keep automatic WireGuard ports out of the fixed legacy port and the common
// Linux ephemeral range. A device retains its port because its node identity is
// already persisted across restarts and upgrades.
const (
	// Keep the Go-core range disjoint from Android's native 10000-29999 range.
	// That makes Android/desktop collisions impossible on the same broken NAT,
	// while leaving 31,000 choices for multiple desktop or iOS devices.
	autoListenPortMin uint16 = 30000
	autoListenPortMax uint16 = 60999
)

// deviceListenPort maps a node identity to a stable installation-specific UDP
// port. Giving devices behind the same NAT distinct source ports avoids broken
// consumer routers that collapse otherwise-distinct 5-tuples when both clients
// connect to the same EXIT.
func deviceListenPort(publicKey types.Key) uint16 {
	digest := sha256.Sum256(append([]byte("ratelmesh-listen-port-v1\x00"), publicKey[:]...))
	span := uint32(autoListenPortMax-autoListenPortMin) + 1
	return autoListenPortMin + uint16(binary.BigEndian.Uint32(digest[:4])%span)
}

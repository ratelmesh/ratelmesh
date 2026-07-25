// Package dns implements MagicDNS (DESIGN.md §3.1): every device gets a stable
// name <device>.<user>.<suffix> that resolves to its mesh IP, so users reach
// peers by name instead of 100.64.x.y. The zone is rebuilt from each netmap; a
// small DNS server answers queries for it and (optionally) forwards the rest.
package dns

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"
	"sync"

	"github.com/shan25519/ratelmesh/internal/types"
)

// DefaultSuffix is the MagicDNS domain suffix.
const DefaultSuffix = "ratelmesh.net"

// Zone is a name->address table for the mesh, safe for concurrent use.
type Zone struct {
	suffix string
	mu     sync.RWMutex
	a      map[string]netip.Addr // fqdn (lowercase, trailing dot) -> IPv4
	aaaa   map[string]netip.Addr // fqdn -> IPv6
}

// NewZone creates an empty zone for the given suffix (default DefaultSuffix).
func NewZone(suffix string) *Zone {
	if suffix == "" {
		suffix = DefaultSuffix
	}
	return &Zone{
		suffix: strings.ToLower(suffix),
		a:      map[string]netip.Addr{},
		aaaa:   map[string]netip.Addr{},
	}
}

// Suffix returns the zone's domain suffix.
func (z *Zone) Suffix() string { return z.suffix }

// FQDN builds a device's fully-qualified MagicDNS name (with trailing dot).
func (z *Zone) FQDN(device, user string) string {
	return sanitizeLabel(device) + "." + sanitizeLabel(user) + "." + z.suffix + "."
}

// Rebuild replaces the zone contents from a netmap's self + peers.
func (z *Zone) Rebuild(self types.Node, peers []types.Node) {
	na := map[string]netip.Addr{}
	naaaa := map[string]netip.Addr{}
	add := func(n types.Node) {
		name := z.FQDN(n.Name, n.User)
		for _, ip := range n.MeshIPs {
			if ip.Is4() {
				na[name] = ip
			} else if ip.Is6() {
				naaaa[name] = ip
			}
		}
	}
	add(self)
	for _, p := range peers {
		add(p)
	}
	z.mu.Lock()
	z.a, z.aaaa = na, naaaa
	z.mu.Unlock()
}

// LookupA resolves an IPv4 record. name may omit the trailing dot.
func (z *Zone) LookupA(name string) (netip.Addr, bool) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	ip, ok := z.a[normalizeName(name)]
	return ip, ok
}

// LookupAAAA resolves an IPv6 record.
func (z *Zone) LookupAAAA(name string) (netip.Addr, bool) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	ip, ok := z.aaaa[normalizeName(name)]
	return ip, ok
}

// Has reports whether the zone knows the name at all (any record type). Used to
// distinguish "name exists, wrong type" (NOERROR) from "no such name" (NXDOMAIN).
func (z *Zone) Has(name string) bool {
	n := normalizeName(name)
	z.mu.RLock()
	defer z.mu.RUnlock()
	_, a := z.a[n]
	_, aaaa := z.aaaa[n]
	return a || aaaa
}

// InZone reports whether a name falls under this zone's suffix.
func (z *Zone) InZone(name string) bool {
	n := strings.TrimSuffix(normalizeName(name), ".")
	return n == z.suffix || strings.HasSuffix(n, "."+z.suffix)
}

func normalizeName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// sanitizeLabel makes a DNS-safe label: lowercase, spaces/underscores to
// hyphens, dropping other invalid characters.
func sanitizeLabel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	original := s
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '_' || r == '-' || r == '.':
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "device"
	}
	if len(out) > 63 {
		sum := sha256.Sum256([]byte(original))
		suffix := hex.EncodeToString(sum[:6])
		stem := strings.TrimRight(out[:63-1-len(suffix)], "-")
		if stem == "" {
			stem = "device"
		}
		out = stem + "-" + suffix
	}
	return out
}

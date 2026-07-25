package remoteaccess

import (
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode"
)

var (
	ErrInvalidServiceKind = errors.New("invalid service kind")
	ErrInvalidPlatform    = errors.New("invalid platform")
	ErrInvalidPort        = errors.New("invalid port")
	ErrInvalidMeshIP      = errors.New("invalid mesh IP")
	ErrInvalidID          = errors.New("invalid ID or label")
	ErrGrantExpired       = errors.New("grant expired")
	ErrGrantNotYetValid   = errors.New("grant not yet valid")
	ErrGrantTooLong       = errors.New("grant duration exceeds maximum lifetime")
	ErrInvalidChronology  = errors.New("invalid grant chronology")
	ErrNilPointer         = errors.New("nil pointer")
	ErrStaleGrant         = errors.New("grant is stale")
	ErrInvalidPolicyVer   = errors.New("invalid policy version")
)

type ServiceKind string

const (
	KindSSH ServiceKind = "ssh"
	KindRDP ServiceKind = "rdp"
	KindVNC ServiceKind = "vnc"
)

type Platform string

const (
	PlatformMacOS   Platform = "macos"
	PlatformWindows Platform = "windows"
	PlatformLinux   Platform = "linux"
	PlatformAndroid Platform = "android"
	PlatformIOS     Platform = "ios"
)

// ServiceAdvertisement represents a locally detected service advertised by a target node.
// It never contains passwords.
type ServiceAdvertisement struct {
	Kind         ServiceKind `json:"kind"`
	Port         uint16      `json:"port"`
	Platform     Platform    `json:"platform"`
	Label        string      `json:"label"`
	TargetNodeID string      `json:"targetNodeId"`
	TargetMeshIP string      `json:"targetMeshIp"`
}

func containsControlChars(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func isMeshAddr(addr netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(addr) ||
		netip.MustParsePrefix("fd00::/8").Contains(addr)
}

// Validate checks that the service advertisement is structurally valid and safe.
func (s *ServiceAdvertisement) Validate() error {
	if s == nil {
		return ErrNilPointer
	}

	if s.Port == 0 {
		return ErrInvalidPort
	}

	if s.TargetNodeID == "" || containsControlChars(s.TargetNodeID) || len(s.TargetNodeID) > 256 {
		return ErrInvalidID
	}

	if strings.TrimSpace(s.Label) == "" || containsControlChars(s.Label) || len(s.Label) > 256 {
		return ErrInvalidID
	}

	addr, err := netip.ParseAddr(s.TargetMeshIP)
	if err != nil {
		return ErrInvalidMeshIP
	}

	// Must be RatelMesh CGNAT 100.64.0.0/10 or IPv6 ULA fd00::/8
	if addr.Is4() {
		prefix := netip.MustParsePrefix("100.64.0.0/10")
		if !prefix.Contains(addr) {
			return ErrInvalidMeshIP
		}
	} else if addr.Is6() {
		// Future ULA rule: allow fd00::/8
		prefix := netip.MustParsePrefix("fd00::/8")
		if !prefix.Contains(addr) {
			return ErrInvalidMeshIP
		}
	} else {
		return ErrInvalidMeshIP
	}

	// Platform and Service compatibility
	switch s.Platform {
	case PlatformMacOS:
		if s.Kind != KindSSH && s.Kind != KindVNC {
			return ErrInvalidServiceKind
		}
	case PlatformWindows:
		if s.Kind != KindSSH && s.Kind != KindRDP {
			return ErrInvalidServiceKind
		}
	case PlatformLinux:
		if s.Kind != KindSSH && s.Kind != KindVNC {
			return ErrInvalidServiceKind
		}
	default:
		return ErrInvalidPlatform
	}

	return nil
}

// Grant represents a bounded temporary grant for remote access.
type Grant struct {
	ID            string               `json:"id"`
	TenantID      string               `json:"tenantId"`
	GrantorID     string               `json:"grantorId"`
	GranteeID     string               `json:"granteeId"`
	GranteeMeshIP string               `json:"granteeMeshIp"`
	PolicyVersion uint64               `json:"policyVersion"`
	Service       ServiceAdvertisement `json:"service"`
	IssuedAt      time.Time            `json:"issuedAt"`
	NotBefore     time.Time            `json:"notBefore"`
	ExpiresAt     time.Time            `json:"expiresAt"`
}

const MaxGrantLifetime = 24 * time.Hour

// Validate checks the grant invariants against the given 'now' time.
func (g *Grant) Validate(now time.Time) error {
	if g == nil {
		return ErrNilPointer
	}

	if g.PolicyVersion == 0 {
		return ErrInvalidPolicyVer
	}

	if g.ID == "" || containsControlChars(g.ID) || len(g.ID) > 256 {
		return ErrInvalidID
	}
	if g.TenantID == "" || containsControlChars(g.TenantID) || len(g.TenantID) > 256 {
		return ErrInvalidID
	}
	if g.GrantorID == "" || containsControlChars(g.GrantorID) || len(g.GrantorID) > 256 {
		return ErrInvalidID
	}
	if g.GranteeID == "" || containsControlChars(g.GranteeID) || len(g.GranteeID) > 256 {
		return ErrInvalidID
	}
	granteeAddr, err := netip.ParseAddr(g.GranteeMeshIP)
	if err != nil || !isMeshAddr(granteeAddr) || granteeAddr.String() != g.GranteeMeshIP {
		return ErrInvalidMeshIP
	}

	if err := g.Service.Validate(); err != nil {
		return err
	}

	if g.IssuedAt.IsZero() || g.NotBefore.IsZero() || g.ExpiresAt.IsZero() {
		return ErrInvalidChronology
	}

	// Chronology validations
	if g.IssuedAt.After(g.NotBefore) {
		return ErrInvalidChronology
	}
	if !g.NotBefore.Before(g.ExpiresAt) {
		return ErrInvalidChronology
	}
	if !g.IssuedAt.Before(g.ExpiresAt) {
		return ErrInvalidChronology
	}

	// Expiry is exclusive: equal to ExpiresAt must be expired.
	if !now.Before(g.ExpiresAt) {
		return ErrGrantExpired
	}

	if now.Before(g.NotBefore) {
		return ErrGrantNotYetValid
	}

	duration := g.ExpiresAt.Sub(g.IssuedAt)
	if duration > MaxGrantLifetime {
		return ErrGrantTooLong
	}

	return nil
}

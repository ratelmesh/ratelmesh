package diagnose

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// The interfaces in this file are the injection seams for the Network Doctor.
// Product code (the daemon and its platform adapters) supplies real
// implementations; tests supply their own doubles inside _test.go files. No
// implementation of these interfaces lives in this package except the
// non-privileged standard-library adapter in stdnet.go, so mocks never leak
// into product code.

// Dialer makes a bounded outbound connection. The standard library's
// *net.Dialer satisfies it directly.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Resolver resolves a host name to addresses. The standard library's
// *net.Resolver satisfies it directly.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// HTTPDoer performs a single HTTP round trip. The standard library's
// *http.Client satisfies it directly.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// QUICProber performs a real TLS-over-QUIC handshake and verifies that the
// target negotiated HTTP/3. A UDP socket opening or write alone must never
// count as success: it proves neither return-path reachability nor QUIC.
type QUICProber interface {
	ProbeQUIC(ctx context.Context, host string, port int) error
}

// PathMTUProber measures the largest payload that traverses a path to dst
// without fragmentation, searching within [low, high]. It is optional: a nil
// PathMTUProber makes the MTU probe fall back to the interface MTU recorded in
// the snapshot. Platform adapters implement it (for example with DF-flagged UDP
// probing) and inject it later.
type PathMTUProber interface {
	ProbeMTU(ctx context.Context, dst string, low, high int) (mtu int, err error)
}

// Clock returns the current time. It is injectable so reports can be made
// deterministic in tests; production uses SystemClock.
type Clock interface {
	Now() time.Time
}

// SystemClock is the real-time Clock used in production.
type SystemClock struct{}

// Now returns the current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }

// Deps bundles the injected capabilities a Doctor uses. Dialer, Resolver and
// HTTP are required for the network probes. QUIC and MTU are optional: a nil
// QUIC prober emits explicit "not tested" evidence rather than inferring HTTP/3
// from HTTPS, and a nil MTU prober falls back to link MTU. Clock defaults to
// SystemClock.
type Deps struct {
	Dialer   Dialer
	Resolver Resolver
	HTTP     HTTPDoer
	QUIC     QUICProber    // optional; nil means HTTP/3 capability was not tested
	MTU      PathMTUProber // optional
	Clock    Clock         // optional; defaults to SystemClock
}

func (d Deps) clock() Clock {
	if d.Clock != nil {
		return d.Clock
	}
	return SystemClock{}
}

// Endpoint identifies a network service the doctor probes. Host may be a
// hostname or a literal IP; both are treated as network identifiers and are
// redacted in the report.
type Endpoint struct {
	// Label is a stable, non-sensitive category (for example "coordinator" or
	// "media-canary") that survives redaction so the report stays legible.
	Label string
	Host  string
	Port  int
	// Scheme, when set (for example "https"), enables an application-level
	// health check in addition to the TCP dial.
	Scheme string
	// HealthPath is an optional HTTP path used for the health check.
	HealthPath string
	// EvidenceSource is a trusted, non-sensitive operator/infrastructure group
	// assigned by the caller. Only unanimous failures from at least two distinct
	// non-empty sources can support a path-wide media finding. DNS names are not
	// evidence sources because aliases can share one physical backend.
	EvidenceSource string
}

// ExitState describes the currently selected exit node, if any.
type ExitState struct {
	// PeerPublicKey identifies the exit peer (a network identifier; redacted).
	PeerPublicKey string
	// LastHandshake is when the exit peer last completed a WireGuard handshake.
	LastHandshake time.Time
	// RoutePresent reports whether the exit's default route is installed.
	RoutePresent bool
	// EgressCanary, when set, is an endpoint reached through the tunnel to
	// confirm the exit actually carries traffic.
	EgressCanary *Endpoint
}

// PeerStatus is one WireGuard peer's liveness.
type PeerStatus struct {
	PublicKey     string // network identifier; redacted
	LastHandshake time.Time
	IsExit        bool

	// RxBytes and TxBytes are the current cumulative WireGuard counters. They
	// are useful evidence even without a baseline, but a single cumulative
	// sample can never prove a stalled path.
	RxBytes int64
	TxBytes int64

	// PreviousRxBytes/PreviousTxBytes and CounterWindow form a trusted baseline
	// only when CountersObserved is true. TrafficExpected must be set only when
	// the caller has independent evidence that traffic should have crossed this
	// peer during that window. The doctor reports no-progress findings only when
	// all of those conditions hold; idle peers are never labelled blackholed.
	PreviousRxBytes  int64
	PreviousTxBytes  int64
	CounterWindow    time.Duration
	CountersObserved bool
	TrafficExpected  bool
}

// WireGuardState is the data-plane view the daemon hands to the doctor. The
// doctor never reads private keys; only liveness and identifiers appear here.
type WireGuardState struct {
	// Interface is the tunnel interface name (for example "utun6"); empty means
	// WireGuard is not configured.
	Interface string
	// Up reports whether the interface is administratively up.
	Up bool
	// LinkMTU is the interface MTU in bytes, or 0 if unknown.
	LinkMTU int
	Peers   []PeerStatus
}

// AddressFamily distinguishes IPv4 from IPv6 in the snapshot.
type AddressFamily int

const (
	// FamilyV4 is IPv4.
	FamilyV4 AddressFamily = 4
	// FamilyV6 is IPv6.
	FamilyV6 AddressFamily = 6
)

// InterfaceAddr records one address on a physical or tunnel interface.
type InterfaceAddr struct {
	Interface string
	Family    AddressFamily
	Addr      netip.Addr
}

// RouteKind is the closed, typed disposition of a route: whether it egresses a
// physical link, the WireGuard tunnel, or is an intentional blackhole/unreachable
// drop. It is the fail-closed model the coverage analysis needs, because a bare
// "via tunnel?" boolean cannot distinguish an intentional blackhole (which
// contains traffic as safely as the tunnel) from a physical escape (which leaks
// it). Kind is plain data and JSON-friendly; an empty Kind falls back to the
// legacy ViaTunnel bool so existing producers keep working unchanged.
type RouteKind string

const (
	// RouteKindUnspecified means the producer set no explicit kind; the legacy
	// ViaTunnel bool is consulted instead.
	RouteKindUnspecified RouteKind = ""
	// RouteKindPhysical egresses a physical link (a potential escape).
	RouteKindPhysical RouteKind = "physical"
	// RouteKindTunnel egresses the WireGuard tunnel.
	RouteKindTunnel RouteKind = "tunnel"
	// RouteKindBlackhole intentionally drops traffic (blackhole/unreachable/
	// reject). For leak analysis it contains traffic just as safely as the
	// tunnel and is never a physical escape.
	RouteKindBlackhole RouteKind = "blackhole"
	// RouteKindUnknown is the sentinel effectiveKind returns for a non-empty
	// RouteKind the model does not recognise. It is never a legitimate producer
	// value; it exists so a garbled or hostile kind fails closed in coverage
	// (treated as neither a safe containment nor a definite physical escape)
	// rather than borrowing the legacy ViaTunnel bool, which a producer could pair
	// with garbage to forge a "tunnel"=safe verdict.
	RouteKindUnknown RouteKind = "unknown"
)

// Route is one entry from the routing table, in the doctor's minimal view.
type Route struct {
	Destination netip.Prefix
	Interface   string
	// ViaTunnel reports whether this route egresses through the WireGuard
	// tunnel interface rather than a physical link. It is retained for
	// backward compatibility; Kind, when set, is authoritative.
	ViaTunnel bool
	// Kind is the typed disposition of the route. When set (non-empty) it is
	// authoritative and lets the coverage analysis tell an intentional
	// blackhole from a physical escape. When empty, effectiveKind falls back to
	// ViaTunnel.
	Kind RouteKind
}

// effectiveKind resolves the route's typed disposition. ONLY an unspecified
// (empty) Kind may consult the legacy ViaTunnel bool: an empty kind with
// ViaTunnel=true is a tunnel route, and with ViaTunnel=false is treated as
// physical (an unclassified route on a non-tunnel interface is assumed to be a
// physical escape, fail-closed, rather than assumed safe). A non-empty but
// unrecognised Kind is untrusted, possibly hostile input; it must NOT fall back
// to ViaTunnel (which garbage+ViaTunnel=true could exploit to forge a safe
// "tunnel" verdict), so it resolves to RouteKindUnknown and fails closed in
// coverage as neither containment nor a definite physical escape.
func (r Route) effectiveKind() RouteKind {
	switch r.Kind {
	case RouteKindPhysical, RouteKindTunnel, RouteKindBlackhole:
		return r.Kind
	case RouteKindUnspecified:
		if r.ViaTunnel {
			return RouteKindTunnel
		}
		return RouteKindPhysical
	default:
		return RouteKindUnknown
	}
}

// DNSState is the resolver configuration the daemon reports.
type DNSState struct {
	// Servers are the configured resolver addresses (network identifiers;
	// redacted). Empty means no resolver is configured.
	Servers []netip.Addr
	// SearchDomains are the configured search domains.
	SearchDomains []string
	// ViaTunnel reports whether DNS is forced through the tunnel.
	ViaTunnel bool
}

// Snapshot is the read-only, data-only view of node state the daemon passes to
// Doctor.Run. It carries the identifiers the probes need; anything genuinely
// secret goes only in Secrets, which seeds redaction and is never emitted.
type Snapshot struct {
	Coordinator  Endpoint
	Relays       []Endpoint
	Exit         *ExitState
	WireGuard    WireGuardState
	Addresses    []InterfaceAddr
	Routes       []Route
	DNS          DNSState
	MediaTargets []Endpoint
	// ExitActive reports whether an exit is meant to be carrying traffic. It is
	// separate from Exit != nil so the routes/IPv6 probes can distinguish
	// "exit selected" from "exit armed and expected to own the default route".
	ExitActive bool

	// ObservedPathMTU is the most recently measured path MTU in bytes, or 0 if
	// unknown. It is plain data captured by the daemon (typically from the MTU
	// probe's measurement) and is the typed evidence the MTU-lowering repair's
	// precondition uses to prove that lowering the tunnel MTU to the path-safe
	// floor cannot itself raise the MTU and worsen blackholing. It is never used
	// to trust a plan's own claims.
	ObservedPathMTU int

	// Secrets holds any sensitive values (auth keys, session tokens, private
	// key material) the daemon wants guaranteed-scrubbed. They are used only to
	// seed the Redactor with known-secret literals and never appear in output.
	Secrets []string
}

// sensitiveValues collects every literal the report must never expose. It
// includes the explicit Secrets plus the identifiers embedded in the snapshot,
// so the Redactor scrubs them even where they appear inside an error string.
func (s Snapshot) sensitiveValues() []string {
	var vals []string
	vals = append(vals, s.Secrets...)
	add := func(v string) {
		if v != "" {
			vals = append(vals, v)
		}
	}
	add(s.Coordinator.Host)
	for _, r := range s.Relays {
		add(r.Host)
	}
	for _, e := range s.MediaTargets {
		add(e.Host)
	}
	if s.Exit != nil {
		add(s.Exit.PeerPublicKey)
		if s.Exit.EgressCanary != nil {
			add(s.Exit.EgressCanary.Host)
		}
	}
	for _, p := range s.WireGuard.Peers {
		add(p.PublicKey)
	}
	for _, d := range s.DNS.SearchDomains {
		add(d)
	}
	return vals
}

// tokenizedInterfaces returns a shallow snapshot copy whose interface
// identifiers have been replaced before a probe can put them in a report. It
// covers every interface-bearing snapshot source, not just WireGuard. Slice
// backing arrays are copied so callers retain their original snapshot
// unchanged. Equal names map to equal tokens, distinct names remain
// distinguishable, and empty names remain empty.
func (s Snapshot) tokenizedInterfaces(redactor *Redactor) Snapshot {
	token := func(name string) string {
		return redactor.tokenIdentifier("interface", name)
	}

	s.WireGuard.Interface = token(s.WireGuard.Interface)
	if len(s.Addresses) != 0 {
		s.Addresses = append([]InterfaceAddr(nil), s.Addresses...)
		for i := range s.Addresses {
			s.Addresses[i].Interface = token(s.Addresses[i].Interface)
		}
	}
	if len(s.Routes) != 0 {
		s.Routes = append([]Route(nil), s.Routes...)
		for i := range s.Routes {
			s.Routes[i].Interface = token(s.Routes[i].Interface)
		}
	}
	return s
}

// tokenizedReportIdentifiers replaces caller-controlled display labels before
// probes can copy them into findings. Labels and evidence-source names are
// useful for within-run correlation but are not trusted as public text: a
// caller may have populated one with a device or office name. Hosts, keys and
// addresses are handled by the report redactor; filesystem and dependency
// errors never enter findings as raw text.
func (s Snapshot) tokenizedReportIdentifiers(redactor *Redactor) Snapshot {
	s = s.tokenizedInterfaces(redactor)
	tokenEndpoint := func(endpoint Endpoint) Endpoint {
		endpoint.Label = redactor.tokenIdentifier("endpoint", endpoint.Label)
		endpoint.EvidenceSource = redactor.tokenIdentifier("source", endpoint.EvidenceSource)
		return endpoint
	}

	s.Coordinator = tokenEndpoint(s.Coordinator)
	if len(s.Relays) != 0 {
		s.Relays = append([]Endpoint(nil), s.Relays...)
		for i := range s.Relays {
			s.Relays[i] = tokenEndpoint(s.Relays[i])
		}
	}
	if len(s.MediaTargets) != 0 {
		s.MediaTargets = append([]Endpoint(nil), s.MediaTargets...)
		for i := range s.MediaTargets {
			s.MediaTargets[i] = tokenEndpoint(s.MediaTargets[i])
		}
	}
	if s.Exit != nil {
		exit := *s.Exit
		if exit.EgressCanary != nil {
			canary := tokenEndpoint(*exit.EgressCanary)
			exit.EgressCanary = &canary
		}
		s.Exit = &exit
	}
	return s
}

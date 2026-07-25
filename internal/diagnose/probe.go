package diagnose

import (
	"context"
	"net"
	"time"
)

// ProbeID names one of the doctor's checks. The values are stable and appear in
// findings and reports.
type ProbeID string

const (
	ProbeCoordinator ProbeID = "coordinator"
	ProbeRelay       ProbeID = "relay"
	ProbeExit        ProbeID = "exit"
	ProbeWireGuard   ProbeID = "wireguard"
	ProbeMTU         ProbeID = "mtu"
	ProbeDNS         ProbeID = "dns"
	ProbeIPv4        ProbeID = "ipv4"
	ProbeIPv6        ProbeID = "ipv6"
	ProbeRoutes      ProbeID = "routes"
	ProbeMedia       ProbeID = "media"

	// ProbeFramework is the synthetic probe id the runner attaches to framework
	// findings that belong to no specific probe — for example the "no probes were
	// available to run" error. It is never a real, selectable probe.
	ProbeFramework ProbeID = "framework"
)

// canonicalProbeOrder is the fixed order in which probe results and their
// findings appear in a report, regardless of the order they finish running.
var canonicalProbeOrder = []ProbeID{
	ProbeCoordinator,
	ProbeRelay,
	ProbeExit,
	ProbeWireGuard,
	ProbeMTU,
	ProbeDNS,
	ProbeIPv4,
	ProbeIPv6,
	ProbeRoutes,
	ProbeMedia,
}

// probeOrderIndex is the reverse map of canonicalProbeOrder, computed once.
var probeOrderIndex = func() map[ProbeID]int {
	m := make(map[ProbeID]int, len(canonicalProbeOrder))
	for i, id := range canonicalProbeOrder {
		m[id] = i
	}
	return m
}()

// probeOrder returns the canonical sort index for id. Unknown ids sort after
// all known ones but keep a deterministic relative order via their string.
func probeOrder(id ProbeID) int {
	if i, ok := probeOrderIndex[id]; ok {
		return i
	}
	return len(canonicalProbeOrder)
}

// Probe is a single bounded, context-cancellable check. Implementations must
// honour ctx (returning promptly when it is cancelled or its deadline passes),
// must never mutate the Env, and should return findings rather than panic.
type Probe interface {
	ID() ProbeID
	Run(ctx context.Context, env *Env) ProbeResult
}

// ProbeStatus classifies how a probe run ended.
type ProbeStatus string

const (
	// StatusCompleted means the probe ran to completion (its findings stand).
	StatusCompleted ProbeStatus = "completed"
	// StatusTimeout means the probe exceeded its per-probe deadline.
	StatusTimeout ProbeStatus = "timeout"
	// StatusPanic means the probe panicked and was recovered.
	StatusPanic ProbeStatus = "panic"
	// StatusSkipped means the probe was not selected to run.
	StatusSkipped ProbeStatus = "skipped"
	// StatusError means the framework refused to run the probe (for example the
	// live-probe goroutine budget was exhausted). It is distinct from a timeout.
	StatusError ProbeStatus = "error"
)

// ProbeResult is the outcome of one probe. A result always carries its Probe
// id, a Status, timing, and any findings. Framework-level problems (timeout,
// panic) are recorded both as a Status and as a probe.* finding so they surface
// in the report's finding list.
type ProbeResult struct {
	Probe     ProbeID       `json:"probe"`
	Status    ProbeStatus   `json:"status"`
	StartedAt time.Time     `json:"-"`
	Duration  time.Duration `json:"duration"`
	Findings  []Finding     `json:"-"`
}

// add appends a finding to the result.
func (r *ProbeResult) add(f Finding) {
	r.Findings = append(r.Findings, f)
}

// Env is the read-only execution context handed to every probe. It is shared
// across concurrently running probes, so probes must treat it as immutable.
type Env struct {
	Snapshot Snapshot
	Config   Config
	Deps     Deps
	// Redactor is available to probes that want to classify an identifier into
	// its coarse, non-sensitive form for a Summary. The report's guaranteed
	// scrub happens independently at serialisation time.
	Redactor *Redactor
	// Clock is the resolved clock (never nil inside a run).
	Clock Clock
}

// Config tunes the doctor's bounds and targets. Use DefaultConfig and override
// the fields you need; the zero value is not meant to be used directly.
type Config struct {
	// ProbeTimeout caps a single probe's wall-clock runtime.
	ProbeTimeout time.Duration
	// DialTimeout caps a single TCP dial inside a probe.
	DialTimeout time.Duration
	// StaleHandshake is how old a WireGuard handshake may be before it is
	// considered stale.
	StaleHandshake time.Duration
	// CounterMinWindow is the minimum trusted baseline window that may support a
	// WireGuard no-progress finding. Shorter samples remain evidence only.
	CounterMinWindow time.Duration

	// RollbackTimeout bounds how long a repair's rollback may run. Rollback runs
	// under a context detached from the caller's cancellation (so cleanup still
	// happens if the caller gave up mid-apply) but capped by this deadline, so an
	// Executor that ignores cancellation yet honours deadlines can never wedge a
	// repair forever.
	RollbackTimeout time.Duration

	// ApplyTimeout bounds the whole capture/apply/postcondition phase of a single
	// repair. Execute derives the execution context from the caller's context
	// capped by this deadline, so a caller that passes context.Background() (no
	// deadline) can never wedge a repair forever if an Executor honours deadlines
	// but not cancellation. An earlier caller deadline still wins.
	ApplyTimeout time.Duration

	// ConnectivityTarget4 and ConnectivityTarget6 are host:port targets the
	// IPv4/IPv6 probes dial to confirm family reachability.
	ConnectivityTarget4 string
	ConnectivityTarget6 string

	// DNS holds DNS-probe tuning.
	DNS DNSProbeConfig
	// MTU holds MTU-probe tuning.
	MTU MTUProbeConfig
	// Media holds sustained-media-probe tuning.
	Media MediaProbeConfig

	// Probes optionally restricts the run to a subset (in any order). Empty
	// means run every probe.
	Probes []ProbeID

	// RedactionSalt fixes the Redactor salt for deterministic output. When nil,
	// Doctor.Run generates a fresh random salt per run so redaction
	// fingerprints cannot be correlated or brute-forced across reports.
	RedactionSalt []byte
}

// DNSProbeConfig tunes the DNS probe.
type DNSProbeConfig struct {
	// QueryName is the name resolved to test DNS. It should be a stable public
	// name whose answers are known to be public addresses.
	QueryName string
	// SlowThreshold flags resolution slower than this as dns.slow.
	SlowThreshold time.Duration
}

// MTUProbeConfig tunes the MTU probe.
type MTUProbeConfig struct {
	// SafeFloor is the minimum acceptable path MTU; below it is mtu.too_low.
	SafeFloor int
	// SearchLow and SearchHigh bound an active PathMTUProber search.
	SearchLow  int
	SearchHigh int
}

// MediaProbeConfig tunes the sustained media/video reachability probe.
type MediaProbeConfig struct {
	// Samples is how many sequential requests to make per target.
	Samples int
	// Interval is the delay between samples.
	Interval time.Duration
	// RequestTimeout caps a single media request.
	RequestTimeout time.Duration
	// MinSuccessRatio is the fraction of samples that must succeed for the
	// target to count as reachable; below it (but above zero) is intermittent.
	MinSuccessRatio float64
	// SlowThreshold flags a mean request slower than this as media.slow.
	SlowThreshold time.Duration
	// QUICHandshakeTimeout caps the independent TLS-over-QUIC handshake used to
	// establish whether the target can negotiate HTTP/3. It does not cap the
	// HTTPS fallback samples, which retain RequestTimeout.
	QUICHandshakeTimeout time.Duration
}

// DefaultConfig returns production-sane bounds. The connectivity and DNS
// targets are stable, well-known, operator-overridable anycast endpoints; the
// MTU floor matches RatelMesh's path-safe 1280-byte default.
func DefaultConfig() Config {
	return Config{
		ProbeTimeout:        8 * time.Second,
		DialTimeout:         3 * time.Second,
		StaleHandshake:      180 * time.Second,
		CounterMinWindow:    5 * time.Second,
		RollbackTimeout:     30 * time.Second,
		ApplyTimeout:        60 * time.Second,
		ConnectivityTarget4: "1.1.1.1:443",
		ConnectivityTarget6: "[2606:4700:4700::1111]:443",
		DNS: DNSProbeConfig{
			QueryName:     "ratelmesh.com",
			SlowThreshold: 1500 * time.Millisecond,
		},
		MTU: MTUProbeConfig{
			SafeFloor:  1280,
			SearchLow:  1200,
			SearchHigh: 1500,
		},
		Media: MediaProbeConfig{
			Samples:              5,
			Interval:             300 * time.Millisecond,
			RequestTimeout:       4 * time.Second,
			MinSuccessRatio:      0.8,
			SlowThreshold:        2 * time.Second,
			QUICHandshakeTimeout: 2 * time.Second,
		},
	}
}

// withDefaults fills any zero field of c from DefaultConfig so a partially
// populated Config is still usable.
func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.ProbeTimeout <= 0 {
		c.ProbeTimeout = d.ProbeTimeout
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = d.DialTimeout
	}
	if c.StaleHandshake <= 0 {
		c.StaleHandshake = d.StaleHandshake
	}
	if c.CounterMinWindow <= 0 {
		c.CounterMinWindow = d.CounterMinWindow
	}
	if c.RollbackTimeout <= 0 {
		c.RollbackTimeout = d.RollbackTimeout
	}
	if c.ApplyTimeout <= 0 {
		c.ApplyTimeout = d.ApplyTimeout
	}
	if c.ConnectivityTarget4 == "" {
		c.ConnectivityTarget4 = d.ConnectivityTarget4
	}
	if c.ConnectivityTarget6 == "" {
		c.ConnectivityTarget6 = d.ConnectivityTarget6
	}
	if c.DNS.QueryName == "" {
		c.DNS.QueryName = d.DNS.QueryName
	}
	if c.DNS.SlowThreshold <= 0 {
		c.DNS.SlowThreshold = d.DNS.SlowThreshold
	}
	if c.MTU.SafeFloor <= 0 {
		c.MTU.SafeFloor = d.MTU.SafeFloor
	}
	if c.MTU.SearchLow <= 0 {
		c.MTU.SearchLow = d.MTU.SearchLow
	}
	if c.MTU.SearchHigh <= 0 {
		c.MTU.SearchHigh = d.MTU.SearchHigh
	}
	if c.Media.Samples <= 0 {
		c.Media.Samples = d.Media.Samples
	}
	if c.Media.Interval <= 0 {
		c.Media.Interval = d.Media.Interval
	}
	if c.Media.RequestTimeout <= 0 {
		c.Media.RequestTimeout = d.Media.RequestTimeout
	}
	if c.Media.MinSuccessRatio <= 0 {
		c.Media.MinSuccessRatio = d.Media.MinSuccessRatio
	}
	if c.Media.SlowThreshold <= 0 {
		c.Media.SlowThreshold = d.Media.SlowThreshold
	}
	if c.Media.QUICHandshakeTimeout <= 0 {
		c.Media.QUICHandshakeTimeout = d.Media.QUICHandshakeTimeout
	}
	return c
}

// sensitiveValues collects the configurable network identifiers a report must
// never expose verbatim. The IPv4/IPv6 connectivity targets and the DNS query
// name are operator-overridable, so an operator may point them at an internal
// host or private domain that names infrastructure. The structural pattern
// scrubber catches bare IP literals but NOT a bare hostname or a domain:port
// with no scheme, so these are registered as per-run known secrets to guarantee
// they cannot leak — as a bare host, a host:port, or embedded inside a probe's
// error string. Both the full target and, for a host:port, its bare host are
// registered so neither form survives. Stable labels and finding codes are never
// included, so they are not over-redacted.
func (c Config) sensitiveValues() []string {
	var vals []string
	add := func(v string) {
		if v == "" {
			return
		}
		vals = append(vals, v)
		if host, _, err := net.SplitHostPort(v); err == nil && host != "" && host != v {
			vals = append(vals, host)
		}
	}
	add(c.ConnectivityTarget4)
	add(c.ConnectivityTarget6)
	add(c.DNS.QueryName)
	return vals
}

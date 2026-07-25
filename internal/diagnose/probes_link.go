package diagnose

import (
	"context"
	"fmt"
	"net"
	"time"
)

// wireGuardProbe inspects the injected data-plane view: interface state, peer
// count and handshake freshness. It reads no private key material.
type wireGuardProbe struct{}

func (wireGuardProbe) ID() ProbeID { return ProbeWireGuard }

func (wireGuardProbe) Run(ctx context.Context, env *Env) ProbeResult {
	res := ProbeResult{Probe: ProbeWireGuard}
	wg := env.Snapshot.WireGuard

	if wg.Interface == "" {
		res.add(newFinding(ProbeWireGuard, CodeWireGuardNotConfigured,
			"no WireGuard interface is configured", nil))
		return res
	}
	if !wg.Up {
		res.add(newFinding(ProbeWireGuard, CodeWireGuardInterfaceDown,
			"the WireGuard interface is down",
			map[string]string{"interface": wg.Interface}))
		return res
	}
	if len(wg.Peers) == 0 {
		res.add(newFinding(ProbeWireGuard, CodeWireGuardNoPeers,
			"the WireGuard interface has no peers",
			map[string]string{"interface": wg.Interface}))
		return res
	}

	now := env.Clock.Now()
	stale := 0
	counterProblems := 0
	for _, p := range wg.Peers {
		if ok, age := handshakeStale(now, p.LastHandshake, env.Config.StaleHandshake); ok {
			stale++
			res.add(newFinding(ProbeWireGuard, CodeWireGuardHandshakeStale,
				"a WireGuard peer handshake is stale",
				wireGuardPeerEvidence(p, map[string]string{
					"handshake_age": age,
					"is_exit":       fmt.Sprint(p.IsExit),
				})))
			continue
		}
		if finding, ok := wireGuardCounterFinding(p, env.Config.CounterMinWindow); ok {
			counterProblems++
			res.add(finding)
			continue
		}
		res.add(newFinding(ProbeWireGuard, CodeWireGuardPeerCounters,
			"current cumulative WireGuard peer counters were captured; this sample alone does not establish progress or a stall",
			wireGuardPeerEvidence(p, map[string]string{
				"is_exit":           fmt.Sprint(p.IsExit),
				"baseline_observed": fmt.Sprint(p.CountersObserved),
			})))
	}
	if stale == 0 && counterProblems == 0 {
		res.add(newFinding(ProbeWireGuard, CodeWireGuardOK,
			fmt.Sprintf("WireGuard is healthy with %d peers", len(wg.Peers)),
			map[string]string{
				"interface": wg.Interface,
				"peers":     fmt.Sprint(len(wg.Peers)),
			}))
	}
	return res
}

func wireGuardCounterFinding(peer PeerStatus, minWindow time.Duration) (Finding, bool) {
	if !peer.CountersObserved || !peer.TrafficExpected || peer.CounterWindow < minWindow ||
		peer.RxBytes < 0 || peer.TxBytes < 0 ||
		peer.PreviousRxBytes < 0 || peer.PreviousTxBytes < 0 ||
		peer.RxBytes < peer.PreviousRxBytes || peer.TxBytes < peer.PreviousTxBytes {
		return Finding{}, false
	}
	rxDelta := peer.RxBytes - peer.PreviousRxBytes
	txDelta := peer.TxBytes - peer.PreviousTxBytes
	ev := wireGuardPeerEvidence(peer, map[string]string{
		"counter_window_ms": fmt.Sprint(peer.CounterWindow.Milliseconds()),
		"rx_bytes":          fmt.Sprint(peer.RxBytes),
		"tx_bytes":          fmt.Sprint(peer.TxBytes),
		"rx_delta":          fmt.Sprint(rxDelta),
		"tx_delta":          fmt.Sprint(txDelta),
		"traffic_expected":  "true",
	})
	switch {
	case txDelta > 0 && rxDelta == 0:
		return newFinding(ProbeWireGuard, CodeWireGuardReceiveStalled,
			"WireGuard transmitted expected traffic but its receive counter made no progress", ev), true
	case txDelta == 0 && rxDelta == 0:
		return newFinding(ProbeWireGuard, CodeWireGuardCountersStalled,
			"expected WireGuard traffic made no receive or transmit counter progress", ev), true
	default:
		return Finding{}, false
	}
}

func wireGuardPeerEvidence(peer PeerStatus, extra map[string]string) map[string]string {
	ev := make(map[string]string, len(extra)+3)
	ev["peer"] = peer.PublicKey
	ev["rx_bytes"] = fmt.Sprint(peer.RxBytes)
	ev["tx_bytes"] = fmt.Sprint(peer.TxBytes)
	for key, value := range extra {
		ev[key] = value
	}
	return ev
}

// mtuProbe determines the usable path MTU. When a PathMTUProber is injected it
// measures actively and TRUSTS that measurement: a prober error, timeout, or
// non-positive result is reported as a not-OK "could not measure" outcome, never
// papered over by silently falling back to the (typically larger) interface MTU
// — that fallback would hide a real path blackhole behind a healthy-looking
// mtu.ok. The interface-MTU fallback is legitimate only when NO active prober is
// configured at all. A path below the safe floor is critical; a measured path
// below the link MTU (so packets fragment) is a warning.
type mtuProbe struct{}

func (mtuProbe) ID() ProbeID { return ProbeMTU }

func (mtuProbe) Run(ctx context.Context, env *Env) ProbeResult {
	res := ProbeResult{Probe: ProbeMTU}
	cfg := env.Config.MTU
	link := env.Snapshot.WireGuard.LinkMTU

	if env.Deps.MTU != nil {
		// An active prober is configured: its result is authoritative. On any
		// failure we must NOT fall back to the link MTU.
		dst, ok := mtuProbeTarget(env)
		if !ok {
			// Fail closed: with no path the exit/user traffic actually takes, there
			// is nothing safe to measure. Reporting "unknown" is correct; falling back
			// to the Coordinator would measure the wrong (physically-pinned) path.
			res.add(newFinding(ProbeMTU, CodeMTUProbeError,
				"no non-coordinator path MTU target is available; path MTU is unknown and was not inferred from the link MTU",
				map[string]string{
					"search_low":  fmt.Sprint(cfg.SearchLow),
					"search_high": fmt.Sprint(cfg.SearchHigh),
				}))
			return res
		}
		measured, err := env.Deps.MTU.ProbeMTU(ctx, dst, cfg.SearchLow, cfg.SearchHigh)
		if err != nil {
			// Evidence is deliberately non-sensitive: the search bounds are config
			// integers and the error string is scrubbed by the report redactor. The
			// probed destination is not echoed here.
			res.add(newFinding(ProbeMTU, CodeMTUProbeError,
				"the active path MTU probe failed; path MTU is unknown and was not inferred from the link MTU",
				map[string]string{
					"error":       err.Error(),
					"search_low":  fmt.Sprint(cfg.SearchLow),
					"search_high": fmt.Sprint(cfg.SearchHigh),
				}))
			return res
		}
		if measured <= 0 {
			res.add(newFinding(ProbeMTU, CodeMTUProbeError,
				"the active path MTU probe returned no usable measurement; path MTU is unknown",
				map[string]string{
					"measured":    fmt.Sprint(measured),
					"search_low":  fmt.Sprint(cfg.SearchLow),
					"search_high": fmt.Sprint(cfg.SearchHigh),
				}))
			return res
		}
		// A trustworthy active measurement must lie inside the inclusive window
		// [SearchLow, SearchHigh] the prober was asked to search. A positive result
		// outside that window is a broken/unusable measurement (a misbehaving prober,
		// a value from the wrong path, an off-by-a-lot bug): treat it as a probe error
		// (unknown), never mtu.ok, and never let it reach classifyMTU — which would
		// otherwise record it as evMeasuredMTU evidence and let it seed repair
		// planning. This is the fail-closed guard at the probe; measuredPathMTU
		// independently bounds the planning read as defence in depth.
		if measured < cfg.SearchLow || measured > cfg.SearchHigh {
			res.add(newFinding(ProbeMTU, CodeMTUProbeError,
				"the active path MTU probe returned a result outside the inclusive search window; path MTU is unknown",
				map[string]string{
					"measured":    fmt.Sprint(measured),
					"search_low":  fmt.Sprint(cfg.SearchLow),
					"search_high": fmt.Sprint(cfg.SearchHigh),
				}))
			return res
		}
		res.add(classifyMTU(measured, link, cfg))
		return res
	}

	// No active prober: fall back to the interface MTU recorded in the snapshot.
	if link == 0 {
		res.add(newFinding(ProbeMTU, CodeMTUUnknown,
			"path MTU could not be determined (no active prober and no link MTU)", nil))
		return res
	}
	res.add(classifyMTU(0, link, cfg))
	return res
}

// evMeasuredMTU is the evidence key classifyMTU records the actively measured
// path MTU under (present only when an active prober produced a positive value).
// The Diagnose flow reads it back from the RAW, pre-redaction probe result to
// seed Snapshot.ObservedPathMTU for repair planning, so it is intentionally a
// single shared constant rather than a duplicated literal.
const evMeasuredMTU = "measured_mtu"

// mtuProbeTarget selects the destination the active path-MTU prober measures
// against. RatelMesh deliberately pins the Coordinator connection *outside* the
// exit tunnel so control traffic stays reachable even when egress is broken;
// measuring MTU to the Coordinator would therefore probe the physical underlay,
// not the path user traffic actually takes, and silently mis-measure. So the
// Coordinator is never used. Preference, most representative of the carrying
// path first:
//
//  1. the exit's egress canary host, when an exit is active and one is set — it
//     rides the tunnel and is exactly the path whose MTU governs media;
//  2. otherwise the first configured media-target host — a real user-traffic
//     destination;
//  3. otherwise the IPv4 connectivity target, with any :port stripped safely.
//
// It fails closed (ok=false) when none of these yields a non-empty host, so the
// caller reports "could not measure" rather than falling back to the Coordinator
// or probing an empty destination.
func mtuProbeTarget(env *Env) (string, bool) {
	if env.Snapshot.ExitActive {
		if ex := env.Snapshot.Exit; ex != nil && ex.EgressCanary != nil {
			if h := ex.EgressCanary.Host; h != "" {
				return h, true
			}
		}
	}
	for _, t := range env.Snapshot.MediaTargets {
		if t.Host != "" {
			return t.Host, true
		}
	}
	if h := hostOnly(env.Config.ConnectivityTarget4); h != "" {
		return h, true
	}
	return "", false
}

// hostOnly returns the host portion of a "host:port" target, tolerating a bare
// host with no port and an IPv6 literal in brackets. It returns "" only for an
// empty input, so a caller can treat "" as "no target".
func hostOnly(target string) string {
	if target == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(target); err == nil {
		return h
	}
	return target
}

// classifyMTU builds the MTU finding from a measured path MTU (0 when the value
// comes only from the link MTU fallback) and the link MTU. It flags a path below
// the safe floor as critical, a measured path below the link MTU as a warning,
// and anything else as healthy.
func classifyMTU(measured, link int, cfg MTUProbeConfig) Finding {
	effective := measured
	if effective == 0 {
		effective = link
	}
	ev := map[string]string{
		"effective_mtu": fmt.Sprint(effective),
		"safe_floor":    fmt.Sprint(cfg.SafeFloor),
	}
	if measured > 0 {
		ev[evMeasuredMTU] = fmt.Sprint(measured)
	}
	if link > 0 {
		ev["link_mtu"] = fmt.Sprint(link)
	}

	switch {
	case effective < cfg.SafeFloor:
		return newFinding(ProbeMTU, CodeMTUTooLow,
			fmt.Sprintf("path MTU %d is below the safe floor of %d", effective, cfg.SafeFloor), ev)
	case measured > 0 && link > 0 && measured < link:
		return newFinding(ProbeMTU, CodeMTUSuboptimal,
			fmt.Sprintf("path MTU %d is below the link MTU %d; packets will fragment", measured, link), ev)
	default:
		return newFinding(ProbeMTU, CodeMTUOK,
			fmt.Sprintf("path MTU %d is healthy", effective), ev)
	}
}

// routesProbe validates the routing table, with special attention to the
// recurring RatelMesh failure mode where the default route silently falls back
// to the physical link while an exit is meant to own it.
type routesProbe struct{}

func (routesProbe) ID() ProbeID { return ProbeRoutes }

func (routesProbe) Run(ctx context.Context, env *Env) ProbeResult {
	res := ProbeResult{Probe: ProbeRoutes}
	routes := env.Snapshot.Routes

	// A default route is "present" for a family only when routes COMPLETELY cover
	// that family's address space by longest-prefix match — an exact /0, both
	// distinct /1 halves, four /2 quarters, or any set that tiles the space (see
	// hasCompleteDefault). Every address family the node actually uses must have
	// its own complete default: a v6 default can never stand in for a missing v4
	// one (and vice versa), so there is no cross-family OR. Relevance is scoped to
	// the families the node is configured for — the families it holds an interface
	// address in — falling back to the families that appear in the routing table
	// when no address is reported, so a node with no address information still
	// fails closed rather than silently passing.
	fams := relevantRouteFamilies(env.Snapshot)

	problem := false
	if !allFamiliesHaveDefault(routes, fams) {
		problem = true
		res.add(newFinding(ProbeRoutes, CodeRoutesDefaultMissing,
			"no default route is present", nil))
	}

	// When an exit is meant to own the default route, verify IPv4 effective
	// coverage by route specificity, not mere coexistence. A physical default
	// that sits *underneath* complete tunnel/blackhole /1 coverage is the normal
	// working table (the physical default is retained for endpoint recovery) and
	// is NOT a leak. It is a leak only when no complete more-specific
	// tunnel/blackhole coverage exists.
	if env.Snapshot.ExitActive {
		switch defaultCoverage(routes, FamilyV4) {
		case coverageContained:
			// The tunnel/blackhole routes fully own IPv4; any coexisting physical
			// default is kept for endpoint recovery and does not leak.
		case coveragePhysicalEscape:
			problem = true
			res.add(newFinding(ProbeRoutes, CodeRoutesExitDefaultAbsent,
				"an exit is active but the tunnel does not fully own the IPv4 default route", nil))
			res.add(newFinding(ProbeRoutes, CodeRoutesPhysicalFallback,
				"the default route fell back to the physical link while the exit is active", nil))
		case coverageUnknown:
			// Fail closed: no complete tunnel coverage and no definite physical
			// escape observed — report the absent tunnel default without claiming
			// the physical link is leaking.
			problem = true
			res.add(newFinding(ProbeRoutes, CodeRoutesExitDefaultAbsent,
				"an exit is active but no complete tunnel IPv4 default route was observed", nil))
		}
	}

	if !problem {
		res.add(newFinding(ProbeRoutes, CodeRoutesOK,
			fmt.Sprintf("routing table healthy (%d routes)", len(routes)),
			map[string]string{"routes": fmt.Sprint(len(routes))}))
	}
	return res
}

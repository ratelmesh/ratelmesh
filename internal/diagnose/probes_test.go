package diagnose

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func run(p Probe, env *Env) ProbeResult {
	return p.Run(context.Background(), env)
}

type blockingMediaHTTP struct {
	started chan<- struct{}
}

func (b blockingMediaHTTP) Do(req *http.Request) (*http.Response, error) {
	select {
	case b.started <- struct{}{}:
	default:
	}
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestCoordinatorProbe(t *testing.T) {
	t.Run("not configured", func(t *testing.T) {
		res := run(coordinatorProbe{}, directEnv(Snapshot{}, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeCoordinatorNotConfigured) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		snap := Snapshot{Coordinator: Endpoint{Label: "coord", Host: "coord.example.net", Port: 443}}
		deps := permissiveDeps(fixedClock())
		deps.Dialer = newFakeDialer().failAddr("coord.example.net:443")
		res := run(coordinatorProbe{}, directEnv(snap, deps))
		if !hasCode(res.Findings, CodeCoordinatorUnreachable) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("unhealthy", func(t *testing.T) {
		snap := Snapshot{Coordinator: Endpoint{Label: "coord", Host: "coord.example.net", Port: 443, Scheme: "https", HealthPath: "/h"}}
		deps := permissiveDeps(fixedClock())
		deps.HTTP = newFakeHTTP(503, "")
		res := run(coordinatorProbe{}, directEnv(snap, deps))
		if !hasCode(res.Findings, CodeCoordinatorUnhealthy) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("tls error", func(t *testing.T) {
		snap := Snapshot{Coordinator: Endpoint{Label: "coord", Host: "coord.example.net", Port: 443, Scheme: "https"}}
		deps := permissiveDeps(fixedClock())
		deps.HTTP = &fakeHTTP{err: errors.New("tls: handshake failure")}
		res := run(coordinatorProbe{}, directEnv(snap, deps))
		if !hasCode(res.Findings, CodeCoordinatorTLSError) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("ok", func(t *testing.T) {
		snap := Snapshot{Coordinator: Endpoint{Label: "coord", Host: "coord.example.net", Port: 443, Scheme: "https", HealthPath: "/h"}}
		res := run(coordinatorProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeCoordinatorOK) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
}

func TestRelayProbe(t *testing.T) {
	t.Run("none configured", func(t *testing.T) {
		res := run(relayProbe{}, directEnv(Snapshot{}, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRelayNoneConfigured) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("one down one up", func(t *testing.T) {
		snap := Snapshot{Relays: []Endpoint{
			{Label: "r1", Host: "r1.example.net", Port: 443},
			{Label: "r2", Host: "r2.example.net", Port: 443},
		}}
		deps := permissiveDeps(fixedClock())
		deps.Dialer = newFakeDialer().failAddr("r1.example.net:443")
		res := run(relayProbe{}, directEnv(snap, deps))
		if !hasCode(res.Findings, CodeRelayUnreachable) || !hasCode(res.Findings, CodeRelayOK) {
			t.Fatalf("got %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeRelayNoneReachable) {
			t.Fatalf("should not report none-reachable when one relay is up: %+v", res.Findings)
		}
	})
	t.Run("none reachable", func(t *testing.T) {
		snap := Snapshot{Relays: []Endpoint{{Label: "r1", Host: "r1.example.net", Port: 443}}}
		deps := permissiveDeps(fixedClock())
		deps.Dialer = alwaysFailDialer{}
		res := run(relayProbe{}, directEnv(snap, deps))
		if !hasCode(res.Findings, CodeRelayNoneReachable) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
}

func TestExitProbe(t *testing.T) {
	now := fixedClock().t
	base := func() Snapshot {
		return Snapshot{Exit: &ExitState{PeerPublicKey: "cGVlcg==", LastHandshake: now.Add(-5 * time.Second), RoutePresent: true}}
	}
	t.Run("not selected", func(t *testing.T) {
		res := run(exitProbe{}, directEnv(Snapshot{}, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeExitNotSelected) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("stale handshake", func(t *testing.T) {
		snap := base()
		snap.Exit.LastHandshake = now.Add(-10 * time.Minute)
		res := run(exitProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeExitHandshakeStale) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("route missing", func(t *testing.T) {
		snap := base()
		snap.Exit.RoutePresent = false
		res := run(exitProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeExitRouteMissing) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("egress blocked", func(t *testing.T) {
		snap := base()
		snap.Exit.EgressCanary = &Endpoint{Label: "canary", Host: "canary.example.net", Port: 443, Scheme: "https"}
		deps := permissiveDeps(fixedClock())
		deps.HTTP = newFakeHTTP(504, "")
		res := run(exitProbe{}, directEnv(snap, deps))
		if !hasCode(res.Findings, CodeExitEgressBlocked) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("egress blackhole without tunnel-bound canary is inconclusive", func(t *testing.T) {
		res := run(exitProbe{}, directEnv(base(), permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeExitEgressNotTested) || hasCode(res.Findings, CodeExitOK) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("missing HTTP probe is inconclusive", func(t *testing.T) {
		snap := base()
		snap.Exit.EgressCanary = &Endpoint{Label: "canary", Host: "canary.example.net", Port: 443, Scheme: "https"}
		deps := permissiveDeps(fixedClock())
		deps.HTTP = nil
		res := run(exitProbe{}, directEnv(snap, deps))
		if !hasCode(res.Findings, CodeExitEgressNotTested) || hasCode(res.Findings, CodeExitOK) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("ok only after egress succeeds", func(t *testing.T) {
		snap := base()
		snap.Exit.EgressCanary = &Endpoint{Label: "canary", Host: "canary.example.net", Port: 443, Scheme: "https"}
		res := run(exitProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeExitOK) || hasCode(res.Findings, CodeExitEgressNotTested) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
}

func TestDefaultDNSQueryUsesRatelMeshAuthenticatedTarget(t *testing.T) {
	if got := DefaultConfig().DNS.QueryName; got != "ratelmesh.com" {
		t.Fatalf("default DNS query = %q, want ratelmesh.com", got)
	}
}

func TestWireGuardProbe(t *testing.T) {
	now := fixedClock().t
	t.Run("not configured", func(t *testing.T) {
		res := run(wireGuardProbe{}, directEnv(Snapshot{}, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeWireGuardNotConfigured) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("interface down", func(t *testing.T) {
		snap := Snapshot{WireGuard: WireGuardState{Interface: "utun7", Up: false}}
		res := run(wireGuardProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeWireGuardInterfaceDown) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("no peers", func(t *testing.T) {
		snap := Snapshot{WireGuard: WireGuardState{Interface: "utun7", Up: true}}
		res := run(wireGuardProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeWireGuardNoPeers) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("stale peer", func(t *testing.T) {
		snap := Snapshot{WireGuard: WireGuardState{Interface: "utun7", Up: true, Peers: []PeerStatus{
			{PublicKey: "cA==peer", LastHandshake: now.Add(-1 * time.Hour)},
		}}}
		res := run(wireGuardProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeWireGuardHandshakeStale) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("ok", func(t *testing.T) {
		snap := Snapshot{WireGuard: WireGuardState{Interface: "utun7", Up: true, Peers: []PeerStatus{
			{PublicKey: "cGVlcg==", LastHandshake: now.Add(-5 * time.Second)},
		}}}
		res := run(wireGuardProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeWireGuardOK) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("single cumulative sample never implies a stall", func(t *testing.T) {
		snap := Snapshot{WireGuard: WireGuardState{Interface: "utun7", Up: true, Peers: []PeerStatus{{
			PublicKey: "cGVlcg==", LastHandshake: now.Add(-5 * time.Second), IsExit: true,
			RxBytes: 0, TxBytes: 9000,
		}}}}
		res := run(wireGuardProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if hasCode(res.Findings, CodeWireGuardReceiveStalled) ||
			hasCode(res.Findings, CodeWireGuardCountersStalled) ||
			!hasCode(res.Findings, CodeWireGuardOK) ||
			!hasCode(res.Findings, CodeWireGuardPeerCounters) {
			t.Fatalf("one cumulative counter sample must stay evidence-only: %+v", res.Findings)
		}
		var evidence map[string]string
		for _, finding := range res.Findings {
			if finding.Code == CodeWireGuardPeerCounters {
				evidence = finding.Evidence
				break
			}
		}
		if evidence["rx_bytes"] != "0" || evidence["tx_bytes"] != "9000" ||
			evidence["is_exit"] != "true" || evidence["baseline_observed"] != "false" {
			t.Fatalf("current peer counters were not preserved as explicit evidence: %+v", evidence)
		}
	})
	t.Run("trusted baseline detects transmit without receive progress", func(t *testing.T) {
		snap := Snapshot{WireGuard: WireGuardState{Interface: "utun7", Up: true, Peers: []PeerStatus{{
			PublicKey: "cGVlcg==", LastHandshake: now.Add(-5 * time.Second),
			PreviousRxBytes: 100, PreviousTxBytes: 200,
			RxBytes: 100, TxBytes: 500, CounterWindow: 10 * time.Second,
			CountersObserved: true, TrafficExpected: true,
		}}}}
		res := run(wireGuardProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeWireGuardReceiveStalled) || hasCode(res.Findings, CodeWireGuardOK) {
			t.Fatalf("trusted no-receive progress was not surfaced: %+v", res.Findings)
		}
	})
	t.Run("trusted baseline detects no counter progress", func(t *testing.T) {
		snap := Snapshot{WireGuard: WireGuardState{Interface: "utun7", Up: true, Peers: []PeerStatus{{
			PublicKey: "cGVlcg==", LastHandshake: now.Add(-5 * time.Second),
			PreviousRxBytes: 100, PreviousTxBytes: 200,
			RxBytes: 100, TxBytes: 200, CounterWindow: 10 * time.Second,
			CountersObserved: true, TrafficExpected: true,
		}}}}
		res := run(wireGuardProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeWireGuardCountersStalled) || hasCode(res.Findings, CodeWireGuardOK) {
			t.Fatalf("trusted no-counter progress was not surfaced: %+v", res.Findings)
		}
	})
	t.Run("idle or short baselines do not imply a stall", func(t *testing.T) {
		for _, peer := range []PeerStatus{
			{
				PublicKey: "cGVlcg==", LastHandshake: now.Add(-5 * time.Second),
				PreviousRxBytes: 100, PreviousTxBytes: 200,
				RxBytes: 100, TxBytes: 200, CounterWindow: 10 * time.Second,
				CountersObserved: true, TrafficExpected: false,
			},
			{
				PublicKey: "cGVlcg==", LastHandshake: now.Add(-5 * time.Second),
				PreviousRxBytes: 100, PreviousTxBytes: 200,
				RxBytes: 100, TxBytes: 200, CounterWindow: time.Second,
				CountersObserved: true, TrafficExpected: true,
			},
		} {
			snap := Snapshot{WireGuard: WireGuardState{Interface: "utun7", Up: true, Peers: []PeerStatus{peer}}}
			res := run(wireGuardProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
			if hasCode(res.Findings, CodeWireGuardReceiveStalled) ||
				hasCode(res.Findings, CodeWireGuardCountersStalled) ||
				!hasCode(res.Findings, CodeWireGuardOK) {
				t.Fatalf("untrusted baseline produced a stall: %+v", res.Findings)
			}
		}
	})
}

func TestMTUProbe(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.MTU = nil
		res := run(mtuProbe{}, directEnv(Snapshot{}, deps))
		if !hasCode(res.Findings, CodeMTUUnknown) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("too low", func(t *testing.T) {
		// 1250 is inside the search window [1200, 1500] but below the 1280 safe
		// floor, so it is a legitimate in-range measurement that classifies as too
		// low — distinct from an out-of-window result, which is a probe error.
		deps := permissiveDeps(fixedClock())
		deps.MTU = fakeMTU{mtu: 1250}
		res := run(mtuProbe{}, directEnv(Snapshot{}, deps))
		if !hasCode(res.Findings, CodeMTUTooLow) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("suboptimal", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.MTU = fakeMTU{mtu: 1400}
		snap := Snapshot{WireGuard: WireGuardState{Interface: "utun7", Up: true, LinkMTU: 1500}}
		res := run(mtuProbe{}, directEnv(snap, deps))
		if !hasCode(res.Findings, CodeMTUSuboptimal) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("ok from link mtu", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.MTU = nil
		snap := Snapshot{WireGuard: WireGuardState{Interface: "utun7", Up: true, LinkMTU: 1420}}
		res := run(mtuProbe{}, directEnv(snap, deps))
		if !hasCode(res.Findings, CodeMTUOK) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("active prober error does not fall back to link mtu", func(t *testing.T) {
		// A prober is configured but errors/times out. A healthy link MTU is present,
		// but trusting it would paper over a real path blackhole with a green mtu.ok.
		// The probe must instead report a not-OK "could not measure" outcome.
		deps := permissiveDeps(fixedClock())
		deps.MTU = fakeMTU{err: timeoutErr{}}
		snap := Snapshot{WireGuard: WireGuardState{Interface: "utun7", Up: true, LinkMTU: 1500}}
		res := run(mtuProbe{}, directEnv(snap, deps))
		if !hasCode(res.Findings, CodeMTUProbeError) {
			t.Fatalf("a prober error must surface as mtu.probe_error: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeMTUOK) {
			t.Fatalf("a prober error must not fall back to a healthy link-MTU pass: %+v", res.Findings)
		}
		for _, f := range res.Findings {
			if f.Code == CodeMTUProbeError && f.Severity < SeverityWarning {
				t.Fatalf("mtu.probe_error must be at least a warning (not a silent green), got %v", f.Severity)
			}
		}
	})
	t.Run("active prober zero measurement is unusable", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.MTU = fakeMTU{mtu: 0} // no error but no usable value
		snap := Snapshot{WireGuard: WireGuardState{Interface: "utun7", Up: true, LinkMTU: 1500}}
		res := run(mtuProbe{}, directEnv(snap, deps))
		if !hasCode(res.Findings, CodeMTUProbeError) || hasCode(res.Findings, CodeMTUOK) {
			t.Fatalf("a zero-measurement prober must be mtu.probe_error, not a link-MTU pass: %+v", res.Findings)
		}
	})
	t.Run("active prober result above the search window is a probe error", func(t *testing.T) {
		// The prober was asked to search [1200, 1500] but returns 9000 (e.g. a stray
		// jumbo-frame value from the wrong path). A positive-but-out-of-range result
		// must be treated as unknown, never mtu.ok, and must never record measured_mtu
		// evidence that could seed the lower-MTU repair.
		deps := permissiveDeps(fixedClock())
		deps.MTU = fakeMTU{mtu: 9000}
		snap := Snapshot{WireGuard: WireGuardState{Interface: "utun7", Up: true, LinkMTU: 1500}}
		res := run(mtuProbe{}, directEnv(snap, deps))
		if !hasCode(res.Findings, CodeMTUProbeError) {
			t.Fatalf("an above-window measurement must be mtu.probe_error: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeMTUOK) {
			t.Fatalf("an above-window measurement must never be mtu.ok: %+v", res.Findings)
		}
		for _, f := range res.Findings {
			if _, ok := f.Evidence[evMeasuredMTU]; ok {
				t.Fatalf("an out-of-range measurement must not record measured_mtu planning evidence: %+v", f.Evidence)
			}
		}
	})
	t.Run("active prober result below the search window is a probe error", func(t *testing.T) {
		// A positive value below SearchLow (the prober violated its search contract)
		// is likewise unknown, never mtu.ok — and specifically never mtu.too_low,
		// which would falsely present it as a trustworthy sub-floor measurement.
		deps := permissiveDeps(fixedClock())
		deps.MTU = fakeMTU{mtu: 800}
		snap := Snapshot{WireGuard: WireGuardState{Interface: "utun7", Up: true, LinkMTU: 1500}}
		res := run(mtuProbe{}, directEnv(snap, deps))
		if !hasCode(res.Findings, CodeMTUProbeError) {
			t.Fatalf("a below-window measurement must be mtu.probe_error: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeMTUOK) || hasCode(res.Findings, CodeMTUTooLow) {
			t.Fatalf("a below-window measurement must be neither mtu.ok nor mtu.too_low: %+v", res.Findings)
		}
		for _, f := range res.Findings {
			if _, ok := f.Evidence[evMeasuredMTU]; ok {
				t.Fatalf("an out-of-range measurement must not record measured_mtu planning evidence: %+v", f.Evidence)
			}
		}
	})
	t.Run("active prober result at the inclusive window boundaries is usable", func(t *testing.T) {
		// The window is inclusive: SearchLow and SearchHigh are both valid results
		// that reach classification (recording measured_mtu evidence) rather than
		// being rejected as out-of-range probe errors.
		for _, mtu := range []int{1200, 1500} {
			deps := permissiveDeps(fixedClock())
			deps.MTU = fakeMTU{mtu: mtu}
			snap := Snapshot{WireGuard: WireGuardState{Interface: "utun7", Up: true, LinkMTU: mtu}}
			res := run(mtuProbe{}, directEnv(snap, deps))
			if hasCode(res.Findings, CodeMTUProbeError) {
				t.Fatalf("an in-window boundary measurement %d must not be a probe error: %+v", mtu, res.Findings)
			}
			recorded := false
			for _, f := range res.Findings {
				if _, ok := f.Evidence[evMeasuredMTU]; ok {
					recorded = true
				}
			}
			if !recorded {
				t.Fatalf("an in-window boundary measurement %d must reach classification and record measured_mtu: %+v", mtu, res.Findings)
			}
		}
	})
}

func TestDNSProbe(t *testing.T) {
	t.Run("not configured", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.Resolver = nil
		res := run(dnsProbe{}, directEnv(Snapshot{}, deps))
		if !hasCode(res.Findings, CodeDNSNotConfigured) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.Resolver = fakeResolver{err: timeoutErr{}}
		res := run(dnsProbe{}, directEnv(Snapshot{}, deps))
		if !hasCode(res.Findings, CodeDNSTimeout) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("no answer", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.Resolver = fakeResolver{addrs: nil}
		res := run(dnsProbe{}, directEnv(Snapshot{}, deps))
		if !hasCode(res.Findings, CodeDNSNoAnswer) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("poison suspected", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.Resolver = fakeResolver{addrs: addrs("127.0.0.1")}
		res := run(dnsProbe{}, directEnv(Snapshot{}, deps))
		if !hasCode(res.Findings, CodeDNSPoisonSuspected) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("public first answer cannot hide a poisoned later answer", func(t *testing.T) {
		for _, poisoned := range []string{
			"127.0.0.1",
			"0.0.0.0",
			"100.64.0.3",
			"192.168.1.7",
			"169.254.1.1",
			"224.0.0.1",
		} {
			t.Run(poisoned, func(t *testing.T) {
				deps := permissiveDeps(fixedClock())
				deps.Resolver = fakeResolver{addrs: addrs("93.184.216.34", poisoned)}
				res := run(dnsProbe{}, directEnv(Snapshot{}, deps))
				if !hasCode(res.Findings, CodeDNSPoisonSuspected) {
					t.Fatalf("mixed public/poisoned answers escaped detection: %+v", res.Findings)
				}
				if hasCode(res.Findings, CodeDNSOK) {
					t.Fatalf("mixed public/poisoned answers must not be dns.ok: %+v", res.Findings)
				}
			})
		}
	})
	t.Run("ok", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.Resolver = fakeResolver{addrs: addrs("93.184.216.34")}
		res := run(dnsProbe{}, directEnv(Snapshot{}, deps))
		if !hasCode(res.Findings, CodeDNSOK) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("slow", func(t *testing.T) {
		deps := permissiveDeps(newStepClock(3 * time.Second))
		deps.Resolver = fakeResolver{addrs: addrs("93.184.216.34")}
		cfg := fixedSaltConfig()
		cfg.DNS.SlowThreshold = time.Second
		res := run(dnsProbe{}, envWith(Snapshot{}, deps, cfg))
		if !hasCode(res.Findings, CodeDNSOK) || !hasCode(res.Findings, CodeDNSSlow) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
}

func TestFamilyProbes(t *testing.T) {
	v4 := InterfaceAddr{Interface: "en0", Family: FamilyV4, Addr: mustAddr("192.168.1.5")}
	v6 := InterfaceAddr{Interface: "en0", Family: FamilyV6, Addr: mustAddr("2001:db8::5")}

	t.Run("ipv4 unavailable", func(t *testing.T) {
		res := run(ipv4Probe{}, directEnv(Snapshot{}, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeIPv4Unavailable) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("loopback does not establish family availability", func(t *testing.T) {
		snap := Snapshot{Addresses: []InterfaceAddr{
			{Interface: "lo0", Family: FamilyV4, Addr: mustAddr("127.0.0.1")},
			{Interface: "lo0", Family: FamilyV6, Addr: mustAddr("::1")},
		}}
		v4res := run(ipv4Probe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(v4res.Findings, CodeIPv4Unavailable) || hasCode(v4res.Findings, CodeIPv4OK) {
			t.Fatalf("loopback-only IPv4 must be unavailable: %+v", v4res.Findings)
		}
		v6res := run(ipv6Probe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(v6res.Findings, CodeIPv6Unavailable) || hasCode(v6res.Findings, CodeIPv6OK) {
			t.Fatalf("loopback-only IPv6 must be unavailable: %+v", v6res.Findings)
		}
	})
	t.Run("ipv4 unreachable", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.Dialer = alwaysFailDialer{}
		res := run(ipv4Probe{}, directEnv(Snapshot{Addresses: []InterfaceAddr{v4}}, deps))
		if !hasCode(res.Findings, CodeIPv4Unreachable) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("ipv4 ok", func(t *testing.T) {
		res := run(ipv4Probe{}, directEnv(Snapshot{Addresses: []InterfaceAddr{v4}}, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeIPv4OK) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("ipv6 unavailable", func(t *testing.T) {
		res := run(ipv6Probe{}, directEnv(Snapshot{Addresses: []InterfaceAddr{v4}}, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeIPv6Unavailable) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("ipv6 leak risk", func(t *testing.T) {
		snap := Snapshot{
			Addresses:  []InterfaceAddr{v6},
			ExitActive: true,
			Routes:     []Route{{Destination: mustPrefix("::/0"), Interface: "en0", ViaTunnel: false}},
		}
		res := run(ipv6Probe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeIPv6OK) || !hasCode(res.Findings, CodeIPv6LeakRisk) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("ipv6 physical default under tunnel halves is contained", func(t *testing.T) {
		// A physical ::/0 kept for endpoint recovery beneath complete tunnel
		// ::/1 + 8000::/1 coverage is not a leak.
		snap := Snapshot{
			Addresses:  []InterfaceAddr{v6},
			ExitActive: true,
			Routes: []Route{
				{Destination: mustPrefix("::/1"), Interface: "utun7", ViaTunnel: true},
				{Destination: mustPrefix("8000::/1"), Interface: "utun7", ViaTunnel: true},
				{Destination: mustPrefix("::/0"), Interface: "en0", ViaTunnel: false},
			},
		}
		res := run(ipv6Probe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if hasCode(res.Findings, CodeIPv6LeakRisk) || hasCode(res.Findings, CodeIPv6ContainmentUnknown) {
			t.Fatalf("complete tunnel halves must contain IPv6: %+v", res.Findings)
		}
	})
	t.Run("ipv6 blackhole halves are accepted", func(t *testing.T) {
		snap := Snapshot{
			Addresses:  []InterfaceAddr{v6},
			ExitActive: true,
			Routes: []Route{
				{Destination: mustPrefix("::/1"), Interface: "utun7", Kind: RouteKindBlackhole},
				{Destination: mustPrefix("8000::/1"), Interface: "utun7", Kind: RouteKindBlackhole},
			},
		}
		res := run(ipv6Probe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if hasCode(res.Findings, CodeIPv6LeakRisk) || hasCode(res.Findings, CodeIPv6ContainmentUnknown) {
			t.Fatalf("intended IPv6 blackhole halves must be accepted as contained: %+v", res.Findings)
		}
	})
	t.Run("ipv6 containment unknown does not claim safe", func(t *testing.T) {
		// A v6-capable host with an active exit but no v6 default route observed:
		// report the unknown observation rather than claim containment or a leak.
		snap := Snapshot{
			Addresses:  []InterfaceAddr{v6},
			ExitActive: true,
			Routes:     []Route{{Destination: mustPrefix("2001:db8::/48"), Interface: "utun7", ViaTunnel: true}},
		}
		res := run(ipv6Probe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeIPv6ContainmentUnknown) {
			t.Fatalf("an unobserved v6 default under an active exit must report unknown: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeIPv6LeakRisk) {
			t.Fatalf("unknown containment must not be reported as a definite leak: %+v", res.Findings)
		}
	})
	t.Run("ipv6 without a v6 address cannot leak", func(t *testing.T) {
		// No v6 address on the host: even a physical ::/0 cannot leak v6 traffic,
		// so no containment finding is emitted.
		snap := Snapshot{
			Addresses:  []InterfaceAddr{v4},
			ExitActive: true,
			Routes:     []Route{{Destination: mustPrefix("::/0"), Interface: "en0", ViaTunnel: false}},
		}
		res := run(ipv6Probe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if hasCode(res.Findings, CodeIPv6LeakRisk) || hasCode(res.Findings, CodeIPv6ContainmentUnknown) {
			t.Fatalf("no v6 address means no v6 containment finding: %+v", res.Findings)
		}
	})
}

func TestRoutesProbe(t *testing.T) {
	t.Run("default missing", func(t *testing.T) {
		res := run(routesProbe{}, directEnv(Snapshot{}, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesDefaultMissing) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("exit default absent and physical fallback", func(t *testing.T) {
		snap := Snapshot{ExitActive: true, Routes: []Route{
			{Destination: mustPrefix("0.0.0.0/0"), Interface: "en0", ViaTunnel: false},
		}}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesExitDefaultAbsent) || !hasCode(res.Findings, CodeRoutesPhysicalFallback) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("physical default under complete tunnel halves is the working table", func(t *testing.T) {
		// The known-good macOS/Unix EXIT table: a physical 0.0.0.0/0 (kept for
		// endpoint recovery) sits UNDERNEATH two more-specific tunnel /1 halves
		// that own all IPv4 by longest-prefix match. This must read as healthy —
		// not a physical fallback, not an absent tunnel default.
		snap := Snapshot{ExitActive: true, Routes: []Route{
			{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", ViaTunnel: true},
			{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", ViaTunnel: true},
			{Destination: mustPrefix("0.0.0.0/0"), Interface: "en0", ViaTunnel: false},
		}}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesOK) {
			t.Fatalf("complete tunnel halves over a physical default must be OK: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeRoutesPhysicalFallback) {
			t.Fatalf("a physical default under complete tunnel coverage is not a fallback leak: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeRoutesExitDefaultAbsent) {
			t.Fatalf("tunnel halves should satisfy the exit default: %+v", res.Findings)
		}
	})
	t.Run("physical escape on one half is a leak", func(t *testing.T) {
		// Only one half is tunnel-owned; the other half falls to the physical
		// default, so IPv4 genuinely escapes and it must be flagged.
		snap := Snapshot{ExitActive: true, Routes: []Route{
			{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", ViaTunnel: true},
			{Destination: mustPrefix("0.0.0.0/0"), Interface: "en0", ViaTunnel: false},
		}}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesPhysicalFallback) {
			t.Fatalf("a half-covered default with a physical escape must flag fallback: %+v", res.Findings)
		}
	})
	t.Run("duplicate half does not satisfy coverage", func(t *testing.T) {
		// Two copies of the SAME /1 half plus a physical default: the old
		// count-based check (>=2 halves) would have called this covered. By exact
		// prefix, only the low half is tunnel-owned, so the high half escapes.
		snap := Snapshot{ExitActive: true, Routes: []Route{
			{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", ViaTunnel: true},
			{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", ViaTunnel: true},
			{Destination: mustPrefix("0.0.0.0/0"), Interface: "en0", ViaTunnel: false},
		}}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesPhysicalFallback) {
			t.Fatalf("duplicate halves must not satisfy coverage: %+v", res.Findings)
		}
	})
	t.Run("blackhole halves contain the default", func(t *testing.T) {
		// Intentional blackhole halves (a kill switch) own the whole space. A
		// physical default underneath is contained, not a leak.
		snap := Snapshot{ExitActive: true, Routes: []Route{
			{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindBlackhole},
			{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindBlackhole},
			{Destination: mustPrefix("0.0.0.0/0"), Interface: "en0", Kind: RouteKindPhysical},
		}}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesOK) {
			t.Fatalf("blackhole halves must contain the default: %+v", res.Findings)
		}
	})
	t.Run("exit active with no default observed reports absent, not fallback", func(t *testing.T) {
		// A non-default route exists (so the table is not empty) but no default
		// scope for v4: fail closed to exit_default_absent without claiming a
		// physical fallback that was not observed.
		snap := Snapshot{ExitActive: true, Routes: []Route{
			{Destination: mustPrefix("10.0.0.0/8"), Interface: "utun7", ViaTunnel: true},
			{Destination: mustPrefix("::/0"), Interface: "utun7", ViaTunnel: true},
		}}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesExitDefaultAbsent) {
			t.Fatalf("an unobserved v4 default under an active exit must report absent: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeRoutesPhysicalFallback) {
			t.Fatalf("no physical fallback should be claimed when none was observed: %+v", res.Findings)
		}
	})
	t.Run("ok", func(t *testing.T) {
		snap := Snapshot{ExitActive: true, Routes: []Route{
			{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", ViaTunnel: true},
			{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", ViaTunnel: true},
		}}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesOK) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	// The non-exit presence check must require a COMPLETE default (an exact /0,
	// or both distinct /1 halves). A lone half — or duplicates of one half — does
	// not cover the whole address space and must report default_missing, never
	// routes_ok. These pin that split-default coverage is by exact prefix, not by
	// "any default-scope route exists".
	t.Run("non-exit lone v4 low half is not a complete default", func(t *testing.T) {
		snap := Snapshot{Routes: []Route{
			{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", ViaTunnel: true},
		}}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesDefaultMissing) {
			t.Fatalf("a lone v4 low half must be default_missing: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeRoutesOK) {
			t.Fatalf("a lone v4 low half must not be routes_ok: %+v", res.Findings)
		}
	})
	t.Run("non-exit lone v4 high half is not a complete default", func(t *testing.T) {
		snap := Snapshot{Routes: []Route{
			{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", ViaTunnel: true},
		}}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesDefaultMissing) {
			t.Fatalf("a lone v4 high half must be default_missing: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeRoutesOK) {
			t.Fatalf("a lone v4 high half must not be routes_ok: %+v", res.Findings)
		}
	})
	t.Run("non-exit duplicate v4 low half is not a complete default", func(t *testing.T) {
		// Two copies of the SAME /1 half: a count-based check (>=2 halves) would
		// wrongly call this covered. By exact prefix, the high half is absent, so
		// the space is not fully covered.
		snap := Snapshot{Routes: []Route{
			{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", ViaTunnel: true},
			{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", ViaTunnel: true},
		}}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesDefaultMissing) {
			t.Fatalf("duplicate v4 low halves must be default_missing: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeRoutesOK) {
			t.Fatalf("duplicate v4 low halves must not be routes_ok: %+v", res.Findings)
		}
	})
	t.Run("non-exit both distinct v4 halves are a complete default", func(t *testing.T) {
		snap := Snapshot{Routes: []Route{
			{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", ViaTunnel: true},
			{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", ViaTunnel: true},
		}}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesOK) {
			t.Fatalf("both distinct v4 halves must be routes_ok: %+v", res.Findings)
		}
	})
	t.Run("non-exit exact v4 /0 is a complete default", func(t *testing.T) {
		snap := Snapshot{Routes: []Route{
			{Destination: mustPrefix("0.0.0.0/0"), Interface: "utun7", ViaTunnel: true},
		}}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesOK) {
			t.Fatalf("an exact v4 /0 must be routes_ok: %+v", res.Findings)
		}
	})
	t.Run("non-exit lone v6 low half is not a complete default", func(t *testing.T) {
		snap := Snapshot{Routes: []Route{
			{Destination: mustPrefix("::/1"), Interface: "utun7", ViaTunnel: true},
		}}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesDefaultMissing) {
			t.Fatalf("a lone v6 low half must be default_missing: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeRoutesOK) {
			t.Fatalf("a lone v6 low half must not be routes_ok: %+v", res.Findings)
		}
	})
	t.Run("non-exit lone v6 high half is not a complete default", func(t *testing.T) {
		snap := Snapshot{Routes: []Route{
			{Destination: mustPrefix("8000::/1"), Interface: "utun7", ViaTunnel: true},
		}}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesDefaultMissing) {
			t.Fatalf("a lone v6 high half must be default_missing: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeRoutesOK) {
			t.Fatalf("a lone v6 high half must not be routes_ok: %+v", res.Findings)
		}
	})
	t.Run("non-exit duplicate v6 high half is not a complete default", func(t *testing.T) {
		snap := Snapshot{Routes: []Route{
			{Destination: mustPrefix("8000::/1"), Interface: "utun7", ViaTunnel: true},
			{Destination: mustPrefix("8000::/1"), Interface: "utun7", ViaTunnel: true},
		}}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesDefaultMissing) {
			t.Fatalf("duplicate v6 high halves must be default_missing: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeRoutesOK) {
			t.Fatalf("duplicate v6 high halves must not be routes_ok: %+v", res.Findings)
		}
	})
	t.Run("non-exit both distinct v6 halves are a complete default", func(t *testing.T) {
		snap := Snapshot{Routes: []Route{
			{Destination: mustPrefix("::/1"), Interface: "utun7", ViaTunnel: true},
			{Destination: mustPrefix("8000::/1"), Interface: "utun7", ViaTunnel: true},
		}}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesOK) {
			t.Fatalf("both distinct v6 halves must be routes_ok: %+v", res.Findings)
		}
	})
}

// TestHasCompleteDefaultArbitraryPrefixLPM proves default-route presence is
// computed by full longest-prefix-match tiling of the address space, not the old
// "/0 or two /1 halves" rule. Any set of prefixes that covers the space counts
// (a /0, two /1 halves, four /2 quarters, or a mix), and any set that leaves a
// gap does not. Kind is ignored — presence, not disposition.
func TestHasCompleteDefaultArbitraryPrefixLPM(t *testing.T) {
	v4quarter := func(p string) Route {
		return Route{Destination: mustPrefix(p), Interface: "utun7", Kind: RouteKindTunnel}
	}
	cases := []struct {
		name   string
		fam    AddressFamily
		routes []Route
		want   bool
	}{
		{"v4 four /2 quarters tile the space", FamilyV4, []Route{
			v4quarter("0.0.0.0/2"), v4quarter("64.0.0.0/2"),
			v4quarter("128.0.0.0/2"), v4quarter("192.0.0.0/2"),
		}, true},
		{"v4 three /2 quarters leave a gap", FamilyV4, []Route{
			v4quarter("0.0.0.0/2"), v4quarter("64.0.0.0/2"), v4quarter("128.0.0.0/2"),
		}, false},
		{"v4 one /1 half plus its two /2 quarters is complete", FamilyV4, []Route{
			v4quarter("0.0.0.0/1"),   // low half whole
			v4quarter("128.0.0.0/2"), // high half's quarters
			v4quarter("192.0.0.0/2"),
		}, true},
		{"v4 exact /0 is complete", FamilyV4, []Route{
			{Destination: mustPrefix("0.0.0.0/0"), Interface: "en0", Kind: RouteKindPhysical},
		}, true},
		{"v6 four /2 quarters tile the space", FamilyV6, []Route{
			{Destination: mustPrefix("::/2"), Interface: "utun7", Kind: RouteKindTunnel},
			{Destination: mustPrefix("4000::/2"), Interface: "utun7", Kind: RouteKindTunnel},
			{Destination: mustPrefix("8000::/2"), Interface: "utun7", Kind: RouteKindTunnel},
			{Destination: mustPrefix("c000::/2"), Interface: "utun7", Kind: RouteKindTunnel},
		}, true},
		{"v6 lone /2 is not complete", FamilyV6, []Route{
			{Destination: mustPrefix("::/2"), Interface: "utun7", Kind: RouteKindTunnel},
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasCompleteDefault(tc.routes, tc.fam); got != tc.want {
				t.Fatalf("hasCompleteDefault = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRoutesProbeRequiresEachRelevantFamily proves default-route presence is
// required of every address family the node actually uses — there is no
// cross-family OR. A v6-only default can never make a v4 node healthy, four
// tunnel /2 quarters DO establish v4 coverage, and a dual-stack node needs a
// complete default in both families.
func TestRoutesProbeRequiresEachRelevantFamily(t *testing.T) {
	v4 := InterfaceAddr{Interface: "en0", Family: FamilyV4, Addr: mustAddr("198.51.100.7")}
	v6 := InterfaceAddr{Interface: "en0", Family: FamilyV6, Addr: mustAddr("2001:db8::5")}

	t.Run("v6-only default cannot make a v4 node healthy", func(t *testing.T) {
		snap := Snapshot{
			Addresses: []InterfaceAddr{v4},
			Routes: []Route{
				{Destination: mustPrefix("::/0"), Interface: "utun7", ViaTunnel: true},
			},
		}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesDefaultMissing) {
			t.Fatalf("a v4 node with only a v6 default must be default_missing: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeRoutesOK) {
			t.Fatalf("a v4 node with only a v6 default must not be routes_ok: %+v", res.Findings)
		}
	})

	t.Run("four tunnel /2 quarters establish v4 coverage", func(t *testing.T) {
		snap := Snapshot{
			Addresses: []InterfaceAddr{v4},
			Routes: []Route{
				{Destination: mustPrefix("0.0.0.0/2"), Interface: "utun7", ViaTunnel: true},
				{Destination: mustPrefix("64.0.0.0/2"), Interface: "utun7", ViaTunnel: true},
				{Destination: mustPrefix("128.0.0.0/2"), Interface: "utun7", ViaTunnel: true},
				{Destination: mustPrefix("192.0.0.0/2"), Interface: "utun7", ViaTunnel: true},
			},
		}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesOK) {
			t.Fatalf("four tunnel /2 quarters must establish a complete v4 default: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeRoutesDefaultMissing) {
			t.Fatalf("four tunnel /2 quarters must not read as default_missing: %+v", res.Findings)
		}
	})

	t.Run("loopback IPv6 does not make an IPv4-only node dual-stack", func(t *testing.T) {
		snap := Snapshot{
			Addresses: []InterfaceAddr{
				v4,
				{Interface: "lo0", Family: FamilyV4, Addr: mustAddr("127.0.0.1")},
				{Interface: "lo0", Family: FamilyV6, Addr: mustAddr("::1")},
			},
			Routes: []Route{
				{Destination: mustPrefix("0.0.0.0/0"), Interface: "en0", Kind: RouteKindPhysical},
			},
		}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesOK) || hasCode(res.Findings, CodeRoutesDefaultMissing) {
			t.Fatalf("loopback IPv6 must not require an IPv6 default route: %+v", res.Findings)
		}
	})

	t.Run("v4-only default cannot make a v6 node healthy", func(t *testing.T) {
		snap := Snapshot{
			Addresses: []InterfaceAddr{v6},
			Routes: []Route{
				{Destination: mustPrefix("0.0.0.0/0"), Interface: "utun7", ViaTunnel: true},
			},
		}
		res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesDefaultMissing) {
			t.Fatalf("a v6 node with only a v4 default must be default_missing: %+v", res.Findings)
		}
	})

	t.Run("dual-stack node needs a complete default in both families", func(t *testing.T) {
		// v4 default present, v6 absent: still missing because v6 is relevant.
		half := Snapshot{
			Addresses: []InterfaceAddr{v4, v6},
			Routes: []Route{
				{Destination: mustPrefix("0.0.0.0/0"), Interface: "utun7", ViaTunnel: true},
			},
		}
		res := run(routesProbe{}, directEnv(half, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesDefaultMissing) {
			t.Fatalf("a dual-stack node missing the v6 default must be default_missing: %+v", res.Findings)
		}

		// Both families covered: healthy.
		full := Snapshot{
			Addresses: []InterfaceAddr{v4, v6},
			Routes: []Route{
				{Destination: mustPrefix("0.0.0.0/0"), Interface: "utun7", ViaTunnel: true},
				{Destination: mustPrefix("::/0"), Interface: "utun7", ViaTunnel: true},
			},
		}
		res = run(routesProbe{}, directEnv(full, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeRoutesOK) {
			t.Fatalf("a dual-stack node with both defaults must be routes_ok: %+v", res.Findings)
		}
	})
}

// TestDefaultCoverageConflictingDisposition pins the fail-closed rule for an
// exact-prefix conflict: a tunnel/blackhole route and a physical route at the
// SAME prefix are ambiguous without route metric/priority, so coverage must be
// coverageUnknown (never coverageContained). Duplicate same-kind routes are
// harmless — the disposition at the prefix is unchanged.
func TestDefaultCoverageConflictingDisposition(t *testing.T) {
	cases := []struct {
		name   string
		fam    AddressFamily
		routes []Route
		want   routeCoverage
	}{
		{
			name: "v4 safe+physical at same low half is unknown",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "en0", Kind: RouteKindPhysical},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
			},
			want: coverageUnknown,
		},
		{
			name: "v4 safe+physical at the /0 default is unknown",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/0"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("0.0.0.0/0"), Interface: "en0", Kind: RouteKindPhysical},
			},
			want: coverageUnknown,
		},
		{
			name: "v4 safe+physical on both halves is unknown not contained",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "en0", Kind: RouteKindPhysical},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "en0", Kind: RouteKindPhysical},
			},
			want: coverageUnknown,
		},
		{
			name: "v6 safe+physical at same high half is unknown",
			fam:  FamilyV6,
			routes: []Route{
				{Destination: mustPrefix("::/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("8000::/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("8000::/1"), Interface: "en0", Kind: RouteKindPhysical},
			},
			want: coverageUnknown,
		},
		{
			name: "v6 safe+physical at the ::/0 default is unknown",
			fam:  FamilyV6,
			routes: []Route{
				{Destination: mustPrefix("::/0"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("::/0"), Interface: "en0", Kind: RouteKindPhysical},
			},
			want: coverageUnknown,
		},
		{
			name: "v4 duplicate tunnel halves stay contained",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun8", Kind: RouteKindTunnel},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun8", Kind: RouteKindTunnel},
			},
			want: coverageContained,
		},
		{
			name: "v4 duplicate physical halves stay an escape",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "en0", Kind: RouteKindPhysical},
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "en1", Kind: RouteKindPhysical},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
			},
			want: coveragePhysicalEscape,
		},
		{
			name: "v6 duplicate blackhole halves stay contained",
			fam:  FamilyV6,
			routes: []Route{
				{Destination: mustPrefix("::/1"), Interface: "utun7", Kind: RouteKindBlackhole},
				{Destination: mustPrefix("::/1"), Interface: "utun7", Kind: RouteKindBlackhole},
				{Destination: mustPrefix("8000::/1"), Interface: "utun7", Kind: RouteKindBlackhole},
			},
			want: coverageContained,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultCoverage(tc.routes, tc.fam); got != tc.want {
				t.Fatalf("defaultCoverage = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestEffectiveKindOnlyEmptyKindUsesLegacyViaTunnel pins the fail-closed rule for
// Route.effectiveKind: only an empty (unspecified) Kind may consult the legacy
// ViaTunnel bool. A recognised Kind is authoritative and a non-empty but
// unrecognised Kind resolves to RouteKindUnknown regardless of ViaTunnel, so a
// garbled/hostile producer cannot pair garbage with ViaTunnel=true to forge a
// safe "tunnel" verdict.
func TestEffectiveKindOnlyEmptyKindUsesLegacyViaTunnel(t *testing.T) {
	cases := []struct {
		name string
		r    Route
		want RouteKind
	}{
		{"empty kind + via tunnel => tunnel", Route{ViaTunnel: true}, RouteKindTunnel},
		{"empty kind + not via tunnel => physical", Route{ViaTunnel: false}, RouteKindPhysical},
		{"explicit tunnel wins", Route{Kind: RouteKindTunnel}, RouteKindTunnel},
		{"explicit physical wins", Route{Kind: RouteKindPhysical, ViaTunnel: true}, RouteKindPhysical},
		{"explicit blackhole wins", Route{Kind: RouteKindBlackhole}, RouteKindBlackhole},
		// The core regression: garbage Kind must NOT borrow ViaTunnel=true.
		{"garbage kind + via tunnel => unknown", Route{Kind: "garbage", ViaTunnel: true}, RouteKindUnknown},
		{"garbage kind + not via tunnel => unknown", Route{Kind: "garbage", ViaTunnel: false}, RouteKindUnknown},
		{"unknown sentinel stays unknown", Route{Kind: RouteKindUnknown, ViaTunnel: true}, RouteKindUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.effectiveKind(); got != tc.want {
				t.Fatalf("effectiveKind = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDefaultCoverageUnknownKindFailsClosed proves a non-empty garbage RouteKind
// paired with ViaTunnel=true is never classified as safe containment: coverage
// stays unknown (fail-closed), so garbage+ViaTunnel cannot forge a green verdict.
func TestDefaultCoverageUnknownKindFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		fam    AddressFamily
		routes []Route
		want   routeCoverage
	}{
		{
			// A real tunnel half plus a garbage+ViaTunnel half. Under the old code
			// the garbage half borrowed ViaTunnel=true and read as contained, making
			// the whole space falsely safe. It must now be unknown.
			name: "v4 garbage+viatunnel half is not contained",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: "garbage", ViaTunnel: true},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
			},
			want: coverageUnknown,
		},
		{
			name: "v4 garbage+viatunnel on both halves is not contained",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: "garbage", ViaTunnel: true},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: "garbage", ViaTunnel: true},
			},
			want: coverageUnknown,
		},
		{
			// A definite physical escape on one half still wins over an unknown half.
			name: "v4 garbage half plus physical escape is an escape",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: "garbage", ViaTunnel: true},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "en0", Kind: RouteKindPhysical},
			},
			want: coveragePhysicalEscape,
		},
		{
			name: "v6 garbage+viatunnel at ::/0 default is not contained",
			fam:  FamilyV6,
			routes: []Route{
				{Destination: mustPrefix("::/0"), Interface: "utun7", Kind: "garbage", ViaTunnel: true},
			},
			want: coverageUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultCoverage(tc.routes, tc.fam); got != tc.want {
				t.Fatalf("defaultCoverage = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestUnknownHalfDoesNotBorrowSafeDefault pins the fail-closed rule that a
// present, unrecognised RouteKind at a more-specific /1 half is DECISIVELY
// unknown by longest-prefix match: coverageAt/classifySpace must not fall through
// to a less-specific safe /0 and thereby call the space contained. The classic
// forge is "unknown /1 + tunnel other /1 + tunnel /0" — under the old code the
// unknown half was not decisive, borrowed the tunnel /0, and the whole space read
// as contained (a false routes.ok). It must now read as unknown for both
// families, so the v4 routes probe and the v6 containment probe both fail closed.
func TestUnknownHalfDoesNotBorrowSafeDefault(t *testing.T) {
	v4routes := []Route{
		{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: "garbage", ViaTunnel: true},
		{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
		{Destination: mustPrefix("0.0.0.0/0"), Interface: "utun7", Kind: RouteKindTunnel},
	}
	v6routes := []Route{
		{Destination: mustPrefix("::/1"), Interface: "utun7", Kind: "garbage", ViaTunnel: true},
		{Destination: mustPrefix("8000::/1"), Interface: "utun7", Kind: RouteKindTunnel},
		{Destination: mustPrefix("::/0"), Interface: "utun7", Kind: RouteKindTunnel},
	}

	// The unknown half must itself be a DECISIVE unknown so no less-specific prefix
	// is ever consulted for it.
	if cov, decisive := coverageAt(v4routes, FamilyV4, mustPrefix("0.0.0.0/1")); cov != coverageUnknown || !decisive {
		t.Fatalf("present-only-unknown v4 half must be decisive unknown, got cov=%d decisive=%v", cov, decisive)
	}
	if cov, decisive := coverageAt(v6routes, FamilyV6, mustPrefix("::/1")); cov != coverageUnknown || !decisive {
		t.Fatalf("present-only-unknown v6 half must be decisive unknown, got cov=%d decisive=%v", cov, decisive)
	}
	if got := defaultCoverage(v4routes, FamilyV4); got != coverageUnknown {
		t.Fatalf("v4 unknown half must not borrow the safe /0: defaultCoverage = %d, want unknown", got)
	}
	if got := defaultCoverage(v6routes, FamilyV6); got != coverageUnknown {
		t.Fatalf("v6 unknown half must not borrow the safe /0: defaultCoverage = %d, want unknown", got)
	}

	// v4: the routes probe must fail closed to exit_default_absent, never routes.ok.
	v4res := run(routesProbe{}, directEnv(Snapshot{ExitActive: true, Routes: v4routes}, permissiveDeps(fixedClock())))
	if !hasCode(v4res.Findings, CodeRoutesExitDefaultAbsent) {
		t.Fatalf("v4 unknown half must fail closed to exit_default_absent: %+v", v4res.Findings)
	}
	if hasCode(v4res.Findings, CodeRoutesOK) {
		t.Fatalf("v4 unknown half must not read as routes.ok: %+v", v4res.Findings)
	}

	// v6: the containment probe must report unknown, not a silent contained pass.
	v6 := InterfaceAddr{Interface: "en0", Family: FamilyV6, Addr: mustAddr("2001:db8::5")}
	v6res := run(ipv6Probe{}, directEnv(Snapshot{Addresses: []InterfaceAddr{v6}, ExitActive: true, Routes: v6routes}, permissiveDeps(fixedClock())))
	if !hasCode(v6res.Findings, CodeIPv6ContainmentUnknown) {
		t.Fatalf("v6 unknown half must report containment unknown, not a contained pass: %+v", v6res.Findings)
	}
	if hasCode(v6res.Findings, CodeIPv6LeakRisk) {
		t.Fatalf("v6 unknown half must not be reported as a definite leak: %+v", v6res.Findings)
	}
}

// TestRoutesProbeSafePhysicalConflictFailsClosed proves the IPv4 routes probe
// reports the ambiguous safe+physical exact-prefix conflict as an absent tunnel
// default (fail-closed), never as healthy and never as a definite physical leak.
func TestRoutesProbeSafePhysicalConflictFailsClosed(t *testing.T) {
	snap := Snapshot{ExitActive: true, Routes: []Route{
		{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
		{Destination: mustPrefix("0.0.0.0/1"), Interface: "en0", Kind: RouteKindPhysical},
		{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
	}}
	res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
	if !hasCode(res.Findings, CodeRoutesExitDefaultAbsent) {
		t.Fatalf("an ambiguous safe+physical default must fail closed to exit_default_absent: %+v", res.Findings)
	}
	if hasCode(res.Findings, CodeRoutesOK) {
		t.Fatalf("an ambiguous safe+physical default must not read as healthy: %+v", res.Findings)
	}
	if hasCode(res.Findings, CodeRoutesPhysicalFallback) {
		t.Fatalf("no definite physical escape was observed; must not claim a fallback leak: %+v", res.Findings)
	}
}

// TestIPv6ProbeSafePhysicalConflictReportsUnknown proves the IPv6 containment
// probe treats the same exact-prefix conflict as containment-unknown, not as a
// contained (safe) table and not as a definite leak.
func TestIPv6ProbeSafePhysicalConflictReportsUnknown(t *testing.T) {
	v6 := InterfaceAddr{Interface: "en0", Family: FamilyV6, Addr: mustAddr("2001:db8::5")}
	snap := Snapshot{
		Addresses:  []InterfaceAddr{v6},
		ExitActive: true,
		Routes: []Route{
			{Destination: mustPrefix("::/1"), Interface: "utun7", Kind: RouteKindTunnel},
			{Destination: mustPrefix("8000::/1"), Interface: "utun7", Kind: RouteKindTunnel},
			{Destination: mustPrefix("8000::/1"), Interface: "en0", Kind: RouteKindPhysical},
		},
	}
	res := run(ipv6Probe{}, directEnv(snap, permissiveDeps(fixedClock())))
	if !hasCode(res.Findings, CodeIPv6ContainmentUnknown) {
		t.Fatalf("an ambiguous safe+physical v6 default must report containment unknown: %+v", res.Findings)
	}
	if hasCode(res.Findings, CodeIPv6LeakRisk) {
		t.Fatalf("an ambiguous v6 default must not be reported as a definite leak: %+v", res.Findings)
	}
}

func TestMediaProbe(t *testing.T) {
	target := Endpoint{Label: "video", Host: "video.example.net", Port: 443, Scheme: "https", HealthPath: "/c"}
	t.Run("not configured", func(t *testing.T) {
		res := run(mediaProbe{}, directEnv(Snapshot{}, permissiveDeps(fixedClock())))
		if !hasCode(res.Findings, CodeMediaNotConfigured) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.HTTP = newFakeHTTP(500, "")
		res := run(mediaProbe{}, directEnv(Snapshot{MediaTargets: []Endpoint{target}}, deps))
		if !hasCode(res.Findings, CodeMediaTargetUnreachable) ||
			!hasCode(res.Findings, CodeMediaEvidenceInconclusive) ||
			hasCode(res.Findings, CodeMediaPathUnreachable) ||
			hasCode(res.Findings, CodeMediaUnreachable) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("intermittent", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		// A real, sustained payload on the 200 sample so it counts as a genuine
		// transfer; the 500s fail, yielding 1/5 — intermittent, not unreachable.
		deps.HTTP = &fakeHTTP{seq: []int{200, 500, 500, 500, 500}, body: mediaBody}
		res := run(mediaProbe{}, directEnv(Snapshot{MediaTargets: []Endpoint{target}}, deps))
		if !hasCode(res.Findings, CodeMediaIntermittent) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("ok", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.QUIC = &fakeQUIC{}
		res := run(mediaProbe{}, directEnv(Snapshot{MediaTargets: []Endpoint{target}}, deps))
		if !hasCode(res.Findings, CodeMediaOK) ||
			!hasCode(res.Findings, CodeMediaQUICOK) ||
			!hasCode(res.Findings, CodeMediaHTTPSFallbackOK) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("failed QUIC is separate from a healthy HTTPS fallback", func(t *testing.T) {
		quicProbe := &fakeQUIC{err: errors.New("blocked or unsupported")}
		deps := permissiveDeps(fixedClock())
		deps.QUIC = quicProbe
		res := run(mediaProbe{}, directEnv(Snapshot{MediaTargets: []Endpoint{target}}, deps))
		if !hasCode(res.Findings, CodeMediaQUICHandshakeFailed) ||
			!hasCode(res.Findings, CodeMediaHTTPSFallbackOK) ||
			!hasCode(res.Findings, CodeMediaOK) ||
			hasCode(res.Findings, CodeMediaHTTPSFallbackFailed) {
			t.Fatalf("QUIC and HTTPS evidence were conflated: %+v", res.Findings)
		}
		quicProbe.mu.Lock()
		defer quicProbe.mu.Unlock()
		if quicProbe.calls != 1 || quicProbe.host != target.Host || quicProbe.port != 443 {
			t.Fatalf("QUIC target = calls:%d %s:%d", quicProbe.calls, quicProbe.host, quicProbe.port)
		}
	})
	t.Run("missing QUIC capability is explicit and does not infer HTTP3 from HTTPS", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.QUIC = nil
		res := run(mediaProbe{}, directEnv(Snapshot{MediaTargets: []Endpoint{target}}, deps))
		if !hasCode(res.Findings, CodeMediaQUICNotTested) ||
			!hasCode(res.Findings, CodeMediaHTTPSFallbackOK) ||
			hasCode(res.Findings, CodeMediaQUICOK) {
			t.Fatalf("missing QUIC dependency was overstated: %+v", res.Findings)
		}
	})
	t.Run("QUIC timeout remains inconclusive while HTTPS is tested independently", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.QUIC = timeoutQUIC{}
		cfg := fixedSaltConfig()
		cfg.Media.QUICHandshakeTimeout = time.Millisecond
		res := run(mediaProbe{}, envWith(Snapshot{MediaTargets: []Endpoint{target}}, deps, cfg))
		if !hasCode(res.Findings, CodeMediaQUICHandshakeFailed) ||
			!hasCode(res.Findings, CodeMediaHTTPSFallbackOK) {
			t.Fatalf("bounded QUIC timeout suppressed HTTPS fallback evidence: %+v", res.Findings)
		}
	})
	t.Run("failed HTTPS fallback is explicit", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.QUIC = &fakeQUIC{}
		deps.HTTP = newFakeHTTP(200, "")
		res := run(mediaProbe{}, directEnv(Snapshot{MediaTargets: []Endpoint{target}}, deps))
		if !hasCode(res.Findings, CodeMediaQUICOK) ||
			!hasCode(res.Findings, CodeMediaHTTPSFallbackFailed) ||
			!hasCode(res.Findings, CodeMediaTargetUnreachable) {
			t.Fatalf("failed HTTPS fallback was not explicit: %+v", res.Findings)
		}
	})
	t.Run("slow", func(t *testing.T) {
		deps := permissiveDeps(newStepClock(3 * time.Second))
		cfg := fixedSaltConfig()
		cfg.Media.SlowThreshold = time.Second
		res := run(mediaProbe{}, envWith(Snapshot{MediaTargets: []Endpoint{target}}, deps, cfg))
		if !hasCode(res.Findings, CodeMediaSlow) {
			t.Fatalf("got %+v", res.Findings)
		}
	})
	t.Run("zero-byte 200 is not a media transfer", func(t *testing.T) {
		// The "webpage opens but the video never plays" case: the status line is a
		// clean 200 but nothing streamed. It must not count as reachable.
		deps := permissiveDeps(fixedClock())
		deps.HTTP = newFakeHTTP(200, "")
		res := run(mediaProbe{}, directEnv(Snapshot{MediaTargets: []Endpoint{target}}, deps))
		if !hasCode(res.Findings, CodeMediaTargetUnreachable) {
			t.Fatalf("a zero-byte 200 must not count as a media transfer: %+v", res.Findings)
		}
	})
	t.Run("204 no content is not a media transfer", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.HTTP = newFakeHTTP(204, "should-be-ignored")
		res := run(mediaProbe{}, directEnv(Snapshot{MediaTargets: []Endpoint{target}}, deps))
		if !hasCode(res.Findings, CodeMediaTargetUnreachable) {
			t.Fatalf("a 204 (no media body) must not count as a media transfer: %+v", res.Findings)
		}
	})
	t.Run("mid-body read error fails the sample", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.HTTP = midBodyErrHTTP{status: 200, prefix: 8, err: errors.New("connection reset by peer")}
		res := run(mediaProbe{}, directEnv(Snapshot{MediaTargets: []Endpoint{target}}, deps))
		if !hasCode(res.Findings, CodeMediaTargetUnreachable) {
			t.Fatalf("a body that errors mid-stream must not count as a transfer: %+v", res.Findings)
		}
	})
	t.Run("206 partial content with payload is a success", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.HTTP = newFakeHTTP(206, mediaBody)
		res := run(mediaProbe{}, directEnv(Snapshot{MediaTargets: []Endpoint{target}}, deps))
		if !hasCode(res.Findings, CodeMediaOK) {
			t.Fatalf("a 206 with a real payload must be reachable: %+v", res.Findings)
		}
	})
	t.Run("closes each response body", func(t *testing.T) {
		closes := 0
		deps := permissiveDeps(fixedClock())
		deps.HTTP = closeCountingHTTP{status: 200, body: "chunk", closes: &closes}
		cfg := fixedSaltConfig()
		cfg.Media.Samples = 3
		_ = run(mediaProbe{}, envWith(Snapshot{MediaTargets: []Endpoint{target}}, deps, cfg))
		if closes == 0 {
			t.Fatal("the media sampler must close every response body")
		}
	})
}

// TestMediaProbeIndependentEvidence prevents a blocked or broken canary from
// being reported as a Mesh/EXIT/path-wide failure. Only unanimous failures
// from at least two trusted sources can produce media.path_unreachable.
func TestMediaProbeIndependentEvidence(t *testing.T) {
	first := Endpoint{Label: "first", Host: "a.example.net", Port: 443, Scheme: "https", HealthPath: "/canary", EvidenceSource: "cdn-a"}
	second := Endpoint{Label: "second", Host: "b.example.net", Port: 443, Scheme: "https", HealthPath: "/canary", EvidenceSource: "cdn-b"}
	config := fixedSaltConfig()
	config.Media.Samples = 1
	config.Media.Interval = 0

	t.Run("one bad and one good is target-specific", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.HTTP = &fakeHTTP{seq: []int{500, 200}, body: mediaBody}
		res := run(mediaProbe{}, envWith(Snapshot{MediaTargets: []Endpoint{second, first}}, deps, config))
		if !hasCode(res.Findings, CodeMediaTargetUnreachable) ||
			!hasCode(res.Findings, CodeMediaOK) ||
			!hasCode(res.Findings, CodeMediaEvidenceInconclusive) {
			t.Fatalf("mixed independent evidence must stay target-specific: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeMediaPathUnreachable) ||
			hasCode(res.Findings, CodeMediaUnreachable) {
			t.Fatalf("one bad canary must not prove a path-wide failure: %+v", res.Findings)
		}
	})

	t.Run("all independent targets bad is path-wide", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.HTTP = &fakeHTTP{seq: []int{500, 500}, body: mediaBody}
		res := run(mediaProbe{}, envWith(Snapshot{MediaTargets: []Endpoint{second, first}}, deps, config))
		if !hasCode(res.Findings, CodeMediaPathUnreachable) ||
			hasCode(res.Findings, CodeMediaUnreachable) {
			t.Fatalf("unanimous independent failures must produce a path-wide finding: %+v", res.Findings)
		}
	})

	t.Run("one configured target is inconclusive", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.HTTP = newFakeHTTP(500, mediaBody)
		res := run(mediaProbe{}, envWith(Snapshot{MediaTargets: []Endpoint{first}}, deps, config))
		if !hasCode(res.Findings, CodeMediaTargetUnreachable) ||
			!hasCode(res.Findings, CodeMediaEvidenceInconclusive) {
			t.Fatalf("one target must be explicitly target-specific and inconclusive: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeMediaPathUnreachable) ||
			hasCode(res.Findings, CodeMediaUnreachable) {
			t.Fatalf("one target cannot prove a path-wide failure: %+v", res.Findings)
		}
	})

	t.Run("one healthy target is still only target-specific evidence", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.HTTP = newFakeHTTP(200, mediaBody)
		res := run(mediaProbe{}, envWith(Snapshot{MediaTargets: []Endpoint{first}}, deps, config))
		if !hasCode(res.Findings, CodeMediaOK) ||
			!hasCode(res.Findings, CodeMediaEvidenceInconclusive) {
			t.Fatalf("one healthy canary still cannot establish a path-wide verdict: %+v", res.Findings)
		}
	})

	t.Run("duplicate endpoints are one evidence source", func(t *testing.T) {
		duplicate := Endpoint{
			Label:          "duplicate",
			Host:           "A.EXAMPLE.NET.",
			Port:           0,
			Scheme:         "HTTPS",
			HealthPath:     "/canary",
			EvidenceSource: "cdn-a",
		}
		deps := permissiveDeps(fixedClock())
		http := &fakeHTTP{seq: []int{500, 500}, body: mediaBody}
		deps.HTTP = http
		res := run(mediaProbe{}, envWith(Snapshot{MediaTargets: []Endpoint{duplicate, first}}, deps, config))
		if !hasCode(res.Findings, CodeMediaEvidenceInconclusive) ||
			hasCode(res.Findings, CodeMediaPathUnreachable) {
			t.Fatalf("duplicate endpoints must not manufacture independent evidence: %+v", res.Findings)
		}
		if http.calls != 1 {
			t.Fatalf("duplicate endpoint was sampled %d times, want 1", http.calls)
		}
	})

	t.Run("conflicting duplicate sources fail closed in either order", func(t *testing.T) {
		conflict := first
		conflict.EvidenceSource = "cdn-b"
		for _, duplicates := range [][]Endpoint{
			{first, conflict},
			{conflict, first},
		} {
			deps := permissiveDeps(fixedClock())
			http := &fakeHTTP{seq: []int{500, 500}, body: mediaBody}
			deps.HTTP = http
			res := run(mediaProbe{}, envWith(Snapshot{
				MediaTargets: append(duplicates, Endpoint{
					Label:          "other",
					Host:           "b.example.net",
					Port:           443,
					Scheme:         "https",
					HealthPath:     "/canary",
					EvidenceSource: "cdn-a",
				}),
			}, deps, config))
			if !hasCode(res.Findings, CodeMediaEvidenceInconclusive) ||
				hasCode(res.Findings, CodeMediaPathUnreachable) {
				t.Fatalf("conflicting duplicate source metadata must be untrusted: %+v", res.Findings)
			}
			if http.calls != 2 {
				t.Fatalf("duplicate endpoint was sampled %d times, want 2 total targets", http.calls)
			}
		}
	})

	t.Run("different URLs in one trusted source are not independent", func(t *testing.T) {
		for _, sameSource := range []Endpoint{
			{Label: "path", Host: first.Host, Port: first.Port, Scheme: first.Scheme, HealthPath: "/another-object", EvidenceSource: first.EvidenceSource},
			{Label: "port", Host: first.Host, Port: 8443, Scheme: first.Scheme, HealthPath: first.HealthPath, EvidenceSource: first.EvidenceSource},
			{Label: "scheme", Host: first.Host, Port: 80, Scheme: "http", HealthPath: first.HealthPath, EvidenceSource: first.EvidenceSource},
			{Label: "dns-alias", Host: "alias.example.net", Port: 443, Scheme: "https", HealthPath: first.HealthPath, EvidenceSource: first.EvidenceSource},
		} {
			deps := permissiveDeps(fixedClock())
			http := &fakeHTTP{seq: []int{500, 500}, body: mediaBody}
			deps.HTTP = http
			res := run(mediaProbe{}, envWith(Snapshot{MediaTargets: []Endpoint{first, sameSource}}, deps, config))
			if !hasCode(res.Findings, CodeMediaEvidenceInconclusive) ||
				hasCode(res.Findings, CodeMediaPathUnreachable) {
				t.Fatalf("one source must not manufacture independent evidence: %+v", res.Findings)
			}
			if http.calls != 2 {
				t.Fatalf("distinct same-source targets were sampled %d times, want 2", http.calls)
			}
		}
	})

	t.Run("missing or malformed source identity cannot support path verdict", func(t *testing.T) {
		for _, source := range []string{"", "cdn a", strings.Repeat("x", 65)} {
			untrusted := second
			untrusted.EvidenceSource = source
			deps := permissiveDeps(fixedClock())
			deps.HTTP = &fakeHTTP{seq: []int{500, 500}, body: mediaBody}
			res := run(mediaProbe{}, envWith(Snapshot{MediaTargets: []Endpoint{first, untrusted}}, deps, config))
			if !hasCode(res.Findings, CodeMediaEvidenceInconclusive) ||
				hasCode(res.Findings, CodeMediaPathUnreachable) {
				t.Fatalf("untrusted source %q produced path evidence: %+v", source, res.Findings)
			}
		}
	})
}

// TestMediaSampleOKThreshold pins the sustained-transfer contract of
// mediaSampleOK: only a documented media status (200/206) that streamed at least
// minMediaSampleBytes with no read error proves a real media transfer.
func TestMediaSampleOKThreshold(t *testing.T) {
	const thr = minMediaSampleBytes
	cases := []struct {
		name   string
		status int
		read   int64
		err    error
		want   bool
	}{
		{"one-byte 200 fails", 200, 1, nil, false},
		{"short clean-EOF body below threshold fails", 200, thr - 1, nil, false},
		{"exactly threshold 200 succeeds", 200, thr, nil, true},
		{"above threshold 206 succeeds", 206, thr + 4096, nil, true},
		{"threshold bytes but mid-stream error fails", 200, thr, errors.New("connection reset"), false},
		{"zero-byte 200 fails", 200, 0, nil, false},
		{"redirect with a big body fails", 302, thr + 1, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mediaSampleOK(c.status, c.read, c.err); got != c.want {
				t.Fatalf("mediaSampleOK(%d, %d, %v) = %v, want %v", c.status, c.read, c.err, got, c.want)
			}
		})
	}
}

// TestMediaProbeRejectsUnsustainedTransfer proves the probe (not just the
// predicate) rejects a payload that opens but does not sustain: a 1-byte body and
// a short clean-EOF body below the threshold both fail, while a body at the
// threshold succeeds.
func TestMediaProbeRejectsUnsustainedTransfer(t *testing.T) {
	target := Endpoint{Label: "video", Host: "video.example.net", Port: 443, Scheme: "https", HealthPath: "/c"}
	t.Run("single-byte body is not a sustained transfer", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.HTTP = newFakeHTTP(200, mediaBody[:1])
		res := run(mediaProbe{}, directEnv(Snapshot{MediaTargets: []Endpoint{target}}, deps))
		if !hasCode(res.Findings, CodeMediaTargetUnreachable) {
			t.Fatalf("a 1-byte 200 must not count as a sustained transfer: %+v", res.Findings)
		}
	})
	t.Run("short clean-EOF body below threshold is not a sustained transfer", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.HTTP = newFakeHTTP(200, mediaBody[:minMediaSampleBytes-1])
		res := run(mediaProbe{}, directEnv(Snapshot{MediaTargets: []Endpoint{target}}, deps))
		if !hasCode(res.Findings, CodeMediaTargetUnreachable) {
			t.Fatalf("a short clean-EOF body must not count as a sustained transfer: %+v", res.Findings)
		}
	})
	t.Run("body at the threshold is a sustained transfer", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.HTTP = newFakeHTTP(200, mediaBody[:minMediaSampleBytes])
		res := run(mediaProbe{}, directEnv(Snapshot{MediaTargets: []Endpoint{target}}, deps))
		if !hasCode(res.Findings, CodeMediaOK) {
			t.Fatalf("a threshold-sized body must count as reachable: %+v", res.Findings)
		}
	})
}

// TestMTUProbeTarget proves the active MTU prober measures the path user traffic
// actually takes — the exit egress canary, else a media target, else the
// connectivity target with its port stripped — and NEVER the coordinator (which
// RatelMesh physically pins outside the exit). It fails closed when no valid
// target exists.
func TestMTUProbeTarget(t *testing.T) {
	const coord = "coord.pinned.example" // physically pinned outside the exit tunnel

	t.Run("prefers the exit egress canary when the exit is active", func(t *testing.T) {
		rec := &recordingMTU{mtu: 1400}
		deps := permissiveDeps(fixedClock())
		deps.MTU = rec
		snap := Snapshot{
			Coordinator:  Endpoint{Label: "coordinator", Host: coord, Port: 443},
			WireGuard:    WireGuardState{Interface: "utun7", Up: true, LinkMTU: 1500},
			ExitActive:   true,
			Exit:         &ExitState{EgressCanary: &Endpoint{Label: "egress", Host: "egress.canary.example", Port: 443}},
			MediaTargets: []Endpoint{{Label: "media", Host: "media.example", Port: 443}},
		}
		run(mtuProbe{}, directEnv(snap, deps))
		if got := rec.lastDst(); got != "egress.canary.example" {
			t.Fatalf("MTU probe must target the exit egress canary, got %q", got)
		}
		if rec.lastDst() == coord {
			t.Fatal("MTU probe must never target the coordinator")
		}
	})

	t.Run("falls back to the first media target when the exit has no canary", func(t *testing.T) {
		rec := &recordingMTU{mtu: 1400}
		deps := permissiveDeps(fixedClock())
		deps.MTU = rec
		snap := Snapshot{
			Coordinator:  Endpoint{Label: "coordinator", Host: coord, Port: 443},
			WireGuard:    WireGuardState{Interface: "utun7", Up: true, LinkMTU: 1500},
			ExitActive:   true, // active, but no egress canary configured
			Exit:         &ExitState{},
			MediaTargets: []Endpoint{{Label: "media", Host: "media.example", Port: 443}},
		}
		run(mtuProbe{}, directEnv(snap, deps))
		if got := rec.lastDst(); got != "media.example" {
			t.Fatalf("MTU probe must fall back to the first media target, got %q", got)
		}
	})

	t.Run("falls back to the connectivity target with the port stripped", func(t *testing.T) {
		rec := &recordingMTU{mtu: 1400}
		deps := permissiveDeps(fixedClock())
		deps.MTU = rec
		snap := Snapshot{
			Coordinator: Endpoint{Label: "coordinator", Host: coord, Port: 443},
			WireGuard:   WireGuardState{Interface: "utun7", Up: true, LinkMTU: 1500},
		}
		cfg := fixedSaltConfig()
		cfg.ConnectivityTarget4 = "203.0.113.9:443"
		run(mtuProbe{}, envWith(snap, deps, cfg))
		if got := rec.lastDst(); got != "203.0.113.9" {
			t.Fatalf("MTU probe must strip the port from the connectivity target, got %q", got)
		}
		if rec.lastDst() == coord {
			t.Fatal("MTU probe must never target the coordinator")
		}
	})

	t.Run("never targets the coordinator even when it is the only endpoint set", func(t *testing.T) {
		rec := &recordingMTU{mtu: 1400}
		deps := permissiveDeps(fixedClock())
		deps.MTU = rec
		snap := Snapshot{
			Coordinator: Endpoint{Label: "coordinator", Host: coord, Port: 443},
			WireGuard:   WireGuardState{Interface: "utun7", Up: true, LinkMTU: 1500},
		}
		// The default connectivity target (1.1.1.1) is the fallback; the coordinator
		// must never be chosen.
		run(mtuProbe{}, directEnv(snap, deps))
		if rec.lastDst() == coord {
			t.Fatalf("MTU probe must never target the coordinator, got %q", rec.lastDst())
		}
	})

	t.Run("fails closed to probe_error without probing when no target exists", func(t *testing.T) {
		rec := &recordingMTU{mtu: 1400}
		// Build an Env directly (bypassing withDefaults) so ConnectivityTarget4 stays
		// empty and there is genuinely no valid target.
		env := &Env{
			Snapshot: Snapshot{WireGuard: WireGuardState{Interface: "utun7", Up: true, LinkMTU: 1500}},
			Config:   Config{MTU: MTUProbeConfig{SafeFloor: 1280, SearchLow: 1200, SearchHigh: 1500}},
			Deps:     Deps{MTU: rec},
			Clock:    fixedClock(),
		}
		if dst, ok := mtuProbeTarget(env); ok {
			t.Fatalf("mtuProbeTarget must fail closed with no target, got dst=%q ok=true", dst)
		}
		res := mtuProbe{}.Run(context.Background(), env)
		if !hasCode(res.Findings, CodeMTUProbeError) {
			t.Fatalf("no target must fail closed to mtu.probe_error: %+v", res.Findings)
		}
		if hasCode(res.Findings, CodeMTUOK) {
			t.Fatalf("no target must not produce a healthy pass: %+v", res.Findings)
		}
		if rec.callCount() != 0 {
			t.Fatalf("the prober must not be called when no target exists, got %d calls", rec.callCount())
		}
	})
}

// TestMediaProbeCancellation proves cancellation before and during a request
// stops promptly and is never counted as target or path failure.
func TestMediaProbeCancellation(t *testing.T) {
	target := Endpoint{Label: "v", Host: "v.example.net", Port: 443, Scheme: "https"}
	assertCancelled := func(t *testing.T, ctx context.Context, env *Env) {
		t.Helper()
		done := make(chan ProbeResult, 1)
		go func() {
			done <- mediaProbe{}.Run(ctx, env)
		}()
		select {
		case res := <-done:
			if hasCode(res.Findings, CodeMediaPathUnreachable) ||
				hasCode(res.Findings, CodeMediaUnreachable) ||
				hasCode(res.Findings, CodeMediaTargetUnreachable) {
				t.Fatalf("cancellation must not be classified as reachability failure: %+v", res.Findings)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("media probe did not honour cancellation")
		}
	}

	t.Run("before sampling", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assertCancelled(t, ctx, directEnv(Snapshot{MediaTargets: []Endpoint{target}}, permissiveDeps(fixedClock())))
	})

	t.Run("during request", func(t *testing.T) {
		started := make(chan struct{}, 1)
		deps := permissiveDeps(fixedClock())
		deps.HTTP = blockingMediaHTTP{started: started}
		cfg := fixedSaltConfig()
		cfg.Media.RequestTimeout = time.Hour
		env := envWith(Snapshot{MediaTargets: []Endpoint{target}}, deps, cfg)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan ProbeResult, 1)
		go func() {
			done <- mediaProbe{}.Run(ctx, env)
		}()
		select {
		case <-started:
			cancel()
		case <-time.After(2 * time.Second):
			t.Fatal("media request did not start")
		}
		select {
		case res := <-done:
			if hasCode(res.Findings, CodeMediaPathUnreachable) ||
				hasCode(res.Findings, CodeMediaUnreachable) ||
				hasCode(res.Findings, CodeMediaTargetUnreachable) {
				t.Fatalf("mid-request cancellation must not be classified as reachability failure: %+v", res.Findings)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("media probe did not stop after mid-request cancellation")
		}
	})
}

// TestDefaultCoverageLongestPrefix exhaustively pins the whole-address-space
// longest-prefix-match coverage analysis for both families: more-specific
// physical/unknown routes that leak or obscure a subtree beneath a safe parent,
// safe specifics that reclaim only their covered subtree, two children jointly
// covering a parent, host routes, order invariance, and invalid/unknown inputs.
// It exercises defaultCoverage directly (the single verdict) so the routes/ipv6
// probes that consume it can never report routes.ok over a leaking subtree.
func TestDefaultCoverageLongestPrefix(t *testing.T) {
	cases := []struct {
		name   string
		fam    AddressFamily
		routes []Route
		want   routeCoverage
	}{
		// --- The core regression: a physical specific under complete safe halves.
		{
			name: "v4 physical /24 under complete tunnel halves leaks its subtree",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("8.8.8.0/24"), Interface: "en0", Kind: RouteKindPhysical},
			},
			want: coveragePhysicalEscape,
		},
		{
			name: "v6 physical /64 under complete tunnel halves leaks its subtree",
			fam:  FamilyV6,
			routes: []Route{
				{Destination: mustPrefix("::/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("8000::/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("2001:db8::/64"), Interface: "en0", Kind: RouteKindPhysical},
			},
			want: coveragePhysicalEscape,
		},
		{
			name: "v4 unknown /24 under complete tunnel halves makes its subtree unknown",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("8.8.8.0/24"), Interface: "en0", Kind: "garbage", ViaTunnel: true},
			},
			want: coverageUnknown,
		},
		// --- Physical parent, safe specifics: only the covered subtree is reclaimed.
		{
			name: "v4 physical /0 under complete tunnel halves is fully contained",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/0"), Interface: "en0", Kind: RouteKindPhysical},
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
			},
			want: coverageContained,
		},
		{
			name: "v4 safe /8 under physical /0 leaves the uncovered parent leaking",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/0"), Interface: "en0", Kind: RouteKindPhysical},
				{Destination: mustPrefix("10.0.0.0/8"), Interface: "utun7", Kind: RouteKindTunnel},
			},
			want: coveragePhysicalEscape,
		},
		{
			name: "v6 safe /32 under physical /0 leaves the uncovered parent leaking",
			fam:  FamilyV6,
			routes: []Route{
				{Destination: mustPrefix("::/0"), Interface: "en0", Kind: RouteKindPhysical},
				{Destination: mustPrefix("2001:db8::/32"), Interface: "utun7", Kind: RouteKindTunnel},
			},
			want: coveragePhysicalEscape,
		},
		// --- Two children fully cover (and override) a parent.
		{
			name: "v4 two tunnel /9 children fully override a physical /8",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("10.0.0.0/8"), Interface: "en0", Kind: RouteKindPhysical},
				{Destination: mustPrefix("10.0.0.0/9"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("10.128.0.0/9"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
			},
			want: coverageContained,
		},
		{
			name: "v4 only one of two /9 children is safe so the /8 subtree still leaks",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("10.0.0.0/8"), Interface: "en0", Kind: RouteKindPhysical},
				{Destination: mustPrefix("10.0.0.0/9"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
			},
			want: coveragePhysicalEscape,
		},
		// --- Host routes (/32, /128).
		{
			name: "v4 physical /32 host route under complete tunnel halves leaks",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("1.2.3.4/32"), Interface: "en0", Kind: RouteKindPhysical},
			},
			want: coveragePhysicalEscape,
		},
		{
			name: "v6 safe /128 host route reclaims only itself under physical /0",
			fam:  FamilyV6,
			routes: []Route{
				{Destination: mustPrefix("::/0"), Interface: "en0", Kind: RouteKindPhysical},
				{Destination: mustPrefix("2001:db8::1/128"), Interface: "utun7", Kind: RouteKindTunnel},
			},
			want: coveragePhysicalEscape,
		},
		{
			name: "v4 blackhole /32 under complete tunnel halves stays contained",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("1.2.3.4/32"), Interface: "utun7", Kind: RouteKindBlackhole},
			},
			want: coverageContained,
		},
		// --- Same-prefix conflict at a deep specific stays unknown (no metric data).
		{
			name: "v4 safe+physical at the same /24 specific is unknown not escape",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("8.8.8.0/24"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("8.8.8.0/24"), Interface: "en0", Kind: RouteKindPhysical},
			},
			want: coverageUnknown,
		},
		// --- Deeply nested override chain: physical /0, safe /8, physical /16.
		{
			name: "v4 physical /16 re-leaks a subtree of a safe /8 under physical /0",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("10.0.0.0/8"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("10.1.0.0/16"), Interface: "en0", Kind: RouteKindPhysical},
			},
			want: coveragePhysicalEscape,
		},
		{
			name: "v4 safe /16 reclaims a physical /8's subtree but the rest still leaks",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("10.0.0.0/8"), Interface: "en0", Kind: RouteKindPhysical},
				{Destination: mustPrefix("10.1.0.0/16"), Interface: "utun7", Kind: RouteKindTunnel},
			},
			want: coveragePhysicalEscape,
		},
		// --- Fully contained deep tree with no physical anywhere.
		{
			name: "v4 nested tunnel specifics over tunnel halves stays contained",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("10.0.0.0/8"), Interface: "utun7", Kind: RouteKindTunnel},
				{Destination: mustPrefix("10.1.0.0/16"), Interface: "utun7", Kind: RouteKindBlackhole},
			},
			want: coverageContained,
		},
		// --- No default at all: uncovered space is unknown, never contained.
		{
			name:   "v4 empty table is unknown",
			fam:    FamilyV4,
			routes: nil,
			want:   coverageUnknown,
		},
		{
			name: "v4 lone tunnel /8 with no default is unknown",
			fam:  FamilyV4,
			routes: []Route{
				{Destination: mustPrefix("10.0.0.0/8"), Interface: "utun7", Kind: RouteKindTunnel},
			},
			want: coverageUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultCoverage(tc.routes, tc.fam); got != tc.want {
				t.Fatalf("defaultCoverage = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestDefaultCoverageOrderInvariance proves the coverage verdict does not depend
// on route ordering: every permutation of a leaking table yields the same escape
// verdict, and every permutation of a contained table yields the same contained
// verdict. Longest-prefix classification must be a set operation.
func TestDefaultCoverageOrderInvariance(t *testing.T) {
	leaking := []Route{
		{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
		{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
		{Destination: mustPrefix("8.8.8.0/24"), Interface: "en0", Kind: RouteKindPhysical},
		{Destination: mustPrefix("0.0.0.0/0"), Interface: "en0", Kind: RouteKindPhysical},
	}
	contained := []Route{
		{Destination: mustPrefix("0.0.0.0/0"), Interface: "en0", Kind: RouteKindPhysical},
		{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
		{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
		{Destination: mustPrefix("8.8.8.0/24"), Interface: "utun7", Kind: RouteKindBlackhole},
	}
	check := func(t *testing.T, routes []Route, want routeCoverage) {
		perm := append([]Route(nil), routes...)
		var rec func(k int)
		rec = func(k int) {
			if k == len(perm) {
				if got := defaultCoverage(perm, FamilyV4); got != want {
					t.Fatalf("permutation %+v: defaultCoverage = %d, want %d", perm, got, want)
				}
				return
			}
			for i := k; i < len(perm); i++ {
				perm[k], perm[i] = perm[i], perm[k]
				rec(k + 1)
				perm[k], perm[i] = perm[i], perm[k]
			}
		}
		rec(0)
	}
	t.Run("leaking table is escape under every ordering", func(t *testing.T) {
		check(t, leaking, coveragePhysicalEscape)
	})
	t.Run("contained table is contained under every ordering", func(t *testing.T) {
		check(t, contained, coverageContained)
	})
}

// TestDefaultCoverageRejectsInvalidRoutes proves invalid destinations and
// wrong-family routes are dropped rather than corrupting the walk, and that
// duplicate routes are harmless. An invalid physical route must not be able to
// forge either a leak or a contained pass.
func TestDefaultCoverageRejectsInvalidRoutes(t *testing.T) {
	// A zero-value (invalid) destination plus wrong-family noise must be ignored,
	// leaving a genuinely contained v4 table contained.
	routes := []Route{
		{Destination: netip.Prefix{}, Interface: "en0", Kind: RouteKindPhysical},
		{Destination: mustPrefix("::/0"), Interface: "en0", Kind: RouteKindPhysical}, // v6 noise
		{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
		{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun8", Kind: RouteKindTunnel}, // dup
		{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
	}
	if got := defaultCoverage(routes, FamilyV4); got != coverageContained {
		t.Fatalf("invalid/wrong-family routes must be dropped, leaving v4 contained: got %d", got)
	}
	// The v6 side of the same table has only a physical ::/0 (the invalid v4 route
	// is dropped), so it is a clean escape.
	if got := defaultCoverage(routes, FamilyV6); got != coveragePhysicalEscape {
		t.Fatalf("v6 physical default must escape: got %d", got)
	}
}

// TestRoutesProbeLeakingSpecificNeverOK proves the IPv4 routes probe surfaces a
// physical specific hiding beneath complete tunnel halves as a leak and never as
// routes.ok — the end-to-end guarantee the coverage algorithm exists to provide.
func TestRoutesProbeLeakingSpecificNeverOK(t *testing.T) {
	snap := Snapshot{ExitActive: true, Routes: []Route{
		{Destination: mustPrefix("0.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
		{Destination: mustPrefix("128.0.0.0/1"), Interface: "utun7", Kind: RouteKindTunnel},
		{Destination: mustPrefix("8.8.8.0/24"), Interface: "en0", Kind: RouteKindPhysical},
	}}
	res := run(routesProbe{}, directEnv(snap, permissiveDeps(fixedClock())))
	if hasCode(res.Findings, CodeRoutesOK) {
		t.Fatalf("a leaking physical /24 must never read as routes.ok: %+v", res.Findings)
	}
	if !hasCode(res.Findings, CodeRoutesPhysicalFallback) {
		t.Fatalf("a leaking physical /24 must be flagged as a physical fallback: %+v", res.Findings)
	}
}

// TestIPv6ProbeLeakingSpecificNeverOK is the IPv6 counterpart: a physical /64
// beneath complete tunnel /1 halves must be reported as a leak risk, not silently
// contained.
func TestIPv6ProbeLeakingSpecificNeverOK(t *testing.T) {
	v6 := InterfaceAddr{Interface: "en0", Family: FamilyV6, Addr: mustAddr("2001:db8::5")}
	snap := Snapshot{
		Addresses:  []InterfaceAddr{v6},
		ExitActive: true,
		Routes: []Route{
			{Destination: mustPrefix("::/1"), Interface: "utun7", Kind: RouteKindTunnel},
			{Destination: mustPrefix("8000::/1"), Interface: "utun7", Kind: RouteKindTunnel},
			{Destination: mustPrefix("2001:db8::/64"), Interface: "en0", Kind: RouteKindPhysical},
		},
	}
	res := run(ipv6Probe{}, directEnv(snap, permissiveDeps(fixedClock())))
	if !hasCode(res.Findings, CodeIPv6LeakRisk) {
		t.Fatalf("a leaking physical /64 must be reported as an IPv6 leak risk: %+v", res.Findings)
	}
}

package diagnose

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestDiagnoseProducesReportAndPlan(t *testing.T) {
	snap, raw := secretSnapshot()
	deps := Deps{
		Dialer:   alwaysFailDialer{},
		Resolver: fakeResolver{addrs: addrs("127.0.0.1")},
		HTTP:     &fakeHTTP{err: timeoutErr{}},
		Clock:    fixedClock(),
	}
	d := New(fixedSaltConfig(), deps)
	report, plan := d.Diagnose(context.Background(), snap)

	if report.Summary.OK {
		t.Fatal("a broken snapshot should not be OK")
	}
	if !plan.DryRun {
		t.Fatal("Diagnose must return a dry-run plan")
	}

	// The plan should target the faults we injected.
	for _, want := range []RepairActionID{
		ActionReconnectCoordinator,
		ActionReapplyRoutes,
		ActionRestartWireGuard,
		ActionRebuildExit,
		ActionFlushDNS,
	} {
		pr, ok := plannedFor(plan, want)
		if !ok {
			t.Errorf("expected plan to include %q", want)
			continue
		}
		if !pr.Applicable {
			t.Errorf("%q should be applicable given the capable snapshot", want)
		}
	}

	// Neither the report nor the plan may leak a raw secret.
	for _, artifact := range [][]byte{mustJSON(t, report), mustJSON(t, plan)} {
		for _, secret := range raw {
			if strings.Contains(string(artifact), secret) {
				t.Errorf("artifact leaked %q", secret)
			}
		}
	}
}

func TestConcurrentRunsAreRaceSafe(t *testing.T) {
	d := New(fixedSaltConfig(), permissiveDeps(fixedClock()))
	snap := healthySnapshot()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := d.Run(context.Background(), snap)
			if r.Summary.TotalFindings == 0 {
				t.Error("expected findings")
			}
		}()
	}
	wg.Wait()
}

// TestStdNetInterfaces is a compile-time check that the standard library types
// satisfy the injection seams, so the daemon can wire them without adapters.
func TestStdNetInterfaces(t *testing.T) {
	deps := NewStdNetDeps()
	if deps.Dialer == nil || deps.Resolver == nil || deps.HTTP == nil || deps.Clock == nil {
		t.Fatal("NewStdNetDeps must populate the core capabilities")
	}
	if deps.MTU != nil {
		t.Fatal("NewStdNetDeps should leave MTU probing to a platform adapter")
	}
}

// TestStdNetAgainstLoopbackServer exercises the real standard-library adapter
// end-to-end against a loopback HTTP server, with the run restricted to the
// probes that need no external network.
func TestStdNetAgainstLoopbackServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Serve a sustained body (above minMediaSampleBytes) so the media probe
		// counts a real transfer, not a webpage-opened-but-no-media stall.
		_, _ = w.Write([]byte(mediaBody))
	}))
	defer srv.Close()

	host, port := splitHostPort(t, srv.URL)
	snap := Snapshot{
		Coordinator:  Endpoint{Label: "coordinator", Host: host, Port: port, Scheme: "http", HealthPath: "/"},
		MediaTargets: []Endpoint{{Label: "video", Host: host, Port: port, Scheme: "http", HealthPath: "/"}},
	}
	cfg := fixedSaltConfig()
	cfg.Probes = []ProbeID{ProbeCoordinator, ProbeMedia}
	cfg.Media.Samples = 2

	report := New(cfg, NewStdNetDeps()).Run(context.Background(), snap)
	if !hasCode(report.Findings, CodeCoordinatorOK) {
		t.Fatalf("expected coordinator.ok via the std adapter, got %+v", report.Findings)
	}
	if !hasCode(report.Findings, CodeMediaOK) {
		t.Fatalf("expected media.ok via the std adapter, got %+v", report.Findings)
	}
}

// TestMeasuredPathMTU pins the evidence contract measuredPathMTU enforces before
// it will seed repair planning: only a completed MTU probe's own measured_mtu
// evidence, strictly positive and within the configured search window, is
// trusted.
func TestMeasuredPathMTU(t *testing.T) {
	cfg := DefaultConfig() // SearchLow 1200, SearchHigh 1500
	mk := func(status ProbeStatus, ev map[string]string) []ProbeResult {
		return []ProbeResult{{Probe: ProbeMTU, Status: status, Findings: []Finding{{Code: CodeMTUSuboptimal, Evidence: ev}}}}
	}
	t.Run("in-bounds measured value is trusted", func(t *testing.T) {
		got, ok := measuredPathMTU(mk(StatusCompleted, map[string]string{evMeasuredMTU: "1400"}), cfg)
		if !ok || got != 1400 {
			t.Fatalf("got %d ok=%v, want 1400 true", got, ok)
		}
	})
	t.Run("out-of-bounds value is rejected", func(t *testing.T) {
		if got, ok := measuredPathMTU(mk(StatusCompleted, map[string]string{evMeasuredMTU: "9000"}), cfg); ok {
			t.Fatalf("an out-of-bounds value must be rejected, got %d", got)
		}
	})
	t.Run("zero and non-numeric values are rejected", func(t *testing.T) {
		if _, ok := measuredPathMTU(mk(StatusCompleted, map[string]string{evMeasuredMTU: "0"}), cfg); ok {
			t.Fatal("zero must be rejected")
		}
		if _, ok := measuredPathMTU(mk(StatusCompleted, map[string]string{evMeasuredMTU: "not-a-number"}), cfg); ok {
			t.Fatal("garbage must be rejected")
		}
	})
	t.Run("a non-completed MTU result is not trusted", func(t *testing.T) {
		if _, ok := measuredPathMTU(mk(StatusTimeout, map[string]string{evMeasuredMTU: "1400"}), cfg); ok {
			t.Fatal("a timed-out MTU result must not seed the path MTU")
		}
	})
	t.Run("a link-only result seeds nothing", func(t *testing.T) {
		if _, ok := measuredPathMTU(mk(StatusCompleted, map[string]string{"link_mtu": "1500"}), cfg); ok {
			t.Fatal("a fallback result without measured_mtu must not seed the path MTU")
		}
	})
}

// TestDiagnoseSeedsMeasuredPathMTUIntoPlan proves the just-measured path MTU flows
// into planning: a suboptimal measured path (below the link) makes the lower-MTU
// repair applicable even though the input Snapshot carried ObservedPathMTU=0,
// while a probe error leaves it inapplicable (fail closed).
func TestDiagnoseSeedsMeasuredPathMTUIntoPlan(t *testing.T) {
	baseSnap := func() Snapshot {
		return Snapshot{
			WireGuard:       WireGuardState{Interface: "utun7", Up: true, LinkMTU: 1500},
			ObservedPathMTU: 0, // the daemon did NOT pre-measure; only the probe will
		}
	}

	t.Run("a suboptimal measured path enables the lower-MTU repair", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.MTU = fakeMTU{mtu: 1400} // below the 1500 link → mtu.suboptimal
		report, plan := New(fixedSaltConfig(), deps).Diagnose(context.Background(), baseSnap())

		if !hasCode(report.Findings, CodeMTUSuboptimal) {
			t.Fatalf("expected a mtu.suboptimal finding, got %+v", report.Findings)
		}
		pr, ok := plannedFor(plan, ActionLowerMTU)
		if !ok {
			t.Fatal("plan must include the lower-MTU repair for a suboptimal path")
		}
		if !pr.Applicable {
			t.Fatalf("lower-MTU must be applicable from the just-measured path evidence: %+v", pr.Preconditions)
		}
	})

	t.Run("a probe error leaves the lower-MTU repair inapplicable", func(t *testing.T) {
		deps := permissiveDeps(fixedClock())
		deps.MTU = fakeMTU{err: timeoutErr{}} // no measurement → nothing to seed
		report, plan := New(fixedSaltConfig(), deps).Diagnose(context.Background(), baseSnap())

		if hasCode(report.Findings, CodeMTUSuboptimal) {
			t.Fatalf("a probe error must not produce mtu.suboptimal: %+v", report.Findings)
		}
		if pr, ok := plannedFor(plan, ActionLowerMTU); ok && pr.Applicable {
			t.Fatalf("lower-MTU must not be applicable after a probe error: %+v", pr.Preconditions)
		}
	})
}

// TestDiagnoseThenExecuteStillRequiresFreshCapture proves the plan-time seeding of
// ObservedPathMTU does NOT weaken execution: even with an applicable lower-MTU
// repair, Execute re-derives evidence at capture time, and an executor that omits
// the fresh path MTU is blocked by the execute-time guard with zero mutation.
func TestDiagnoseThenExecuteStillRequiresFreshCapture(t *testing.T) {
	deps := permissiveDeps(fixedClock())
	deps.MTU = fakeMTU{mtu: 1400}
	d := New(fixedSaltConfig(), deps)

	planSnap := Snapshot{WireGuard: WireGuardState{Interface: "utun7", Up: true, LinkMTU: 1500}}
	_, plan := d.Diagnose(context.Background(), planSnap)
	pr, ok := plannedFor(plan, ActionLowerMTU)
	if !ok || !pr.Applicable {
		t.Fatalf("precondition: lower-MTU must be applicable in the plan, ok=%v applicable=%v", ok, pr.Applicable)
	}

	// The snapshot handed to Execute is captured immediately before execution and
	// carries fresh path evidence, so the execute-time precondition passes; the
	// executor, however, omits the fresh path MTU at CAPTURE, so the guard must
	// fail closed and set no MTU.
	execSnap := Snapshot{
		WireGuard:       WireGuardState{Interface: "utun7", Up: true, LinkMTU: 1500},
		ObservedPathMTU: 1400,
	}
	exec := &fakeExecutor{mtuOmitPath: true}
	rep := d.ExecutePlan(context.Background(), execSnap, plan, exec)
	pe, found := execFor(rep, ActionLowerMTU)
	if !found || pe.Status != RepairSkipped {
		t.Fatalf("the lower-MTU repair must be skipped without fresh path capture, got %q (%s)", pe.Status, pe.Error)
	}
	for _, op := range exec.applied {
		if op == OpSetMTU {
			t.Fatal("Execute must not set the MTU when fresh path evidence is missing")
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func splitHostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	// rawURL looks like http://127.0.0.1:53812
	rest := strings.TrimPrefix(rawURL, "http://")
	host, portStr, ok := strings.Cut(rest, ":")
	if !ok {
		t.Fatalf("cannot split %q", rawURL)
	}
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port
}

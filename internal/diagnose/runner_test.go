package diagnose

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"
)

// findingByCode returns the first finding with the given code, or false.
func findingByCode(fs []Finding, c Code) (Finding, bool) {
	for _, f := range fs {
		if f.Code == c {
			return f, true
		}
	}
	return Finding{}, false
}

func hasCode(fs []Finding, c Code) bool {
	_, ok := findingByCode(fs, c)
	return ok
}

func TestRunBoundedByProbeTimeout(t *testing.T) {
	cfg := fixedSaltConfig()
	cfg.ProbeTimeout = 40 * time.Millisecond
	d := New(cfg, permissiveDeps(fixedClock()), WithProbes(blockingProbe{id: ProbeCoordinator}))

	start := time.Now()
	report := d.Run(context.Background(), Snapshot{})
	elapsed := time.Since(start)

	if elapsed > time.Second {
		t.Fatalf("Run should be bounded by the probe timeout, took %v", elapsed)
	}
	if !hasCode(report.Findings, CodeProbeTimeout) {
		t.Fatalf("expected a probe.timeout finding, got %+v", report.Findings)
	}
	if report.Probes[0].Status != StatusTimeout {
		t.Fatalf("expected StatusTimeout, got %q", report.Probes[0].Status)
	}
}

func TestRunHonoursCancelledContext(t *testing.T) {
	cfg := fixedSaltConfig()
	cfg.ProbeTimeout = 5 * time.Second // large; cancellation should win
	d := New(cfg, permissiveDeps(fixedClock()), WithProbes(blockingProbe{id: ProbeCoordinator}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	start := time.Now()
	_ = d.Run(ctx, Snapshot{})
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Run should return promptly on a cancelled context, took %v", elapsed)
	}
}

func TestRunRecoversPanic(t *testing.T) {
	d := New(fixedSaltConfig(), permissiveDeps(fixedClock()),
		WithProbes(
			panicProbe{id: ProbeCoordinator},
			staticProbe{id: ProbeDNS, code: CodeDNSOK},
		),
	)
	report := d.Run(context.Background(), Snapshot{})

	if !hasCode(report.Findings, CodeProbePanic) {
		t.Fatalf("expected a probe.panic finding, got %+v", report.Findings)
	}
	// The sibling probe must still have produced its finding.
	if !hasCode(report.Findings, CodeDNSOK) {
		t.Fatalf("sibling probe should still run after a panic, got %+v", report.Findings)
	}
	for _, p := range report.Probes {
		if p.Probe == ProbeCoordinator && p.Status != StatusPanic {
			t.Fatalf("panicking probe should report StatusPanic, got %q", p.Status)
		}
	}
}

func TestPartialProbeFailureKeepsSiblings(t *testing.T) {
	d := New(fixedSaltConfig(), permissiveDeps(fixedClock()),
		WithProbes(
			staticProbe{id: ProbeRelay, code: CodeRelayOK},
			panicProbe{id: ProbeExit},
			staticProbe{id: ProbeDNS, code: CodeDNSOK},
			blockingProbe{id: ProbeMedia}, // will time out
		),
	)
	cfg := d.cfg
	cfg.ProbeTimeout = 40 * time.Millisecond
	d.cfg = cfg

	report := d.Run(context.Background(), Snapshot{})
	for _, c := range []Code{CodeRelayOK, CodeDNSOK, CodeProbePanic, CodeProbeTimeout} {
		if !hasCode(report.Findings, c) {
			t.Errorf("expected code %q in a partial-failure run, got %+v", c, report.Findings)
		}
	}
}

func TestDeterministicReportBytes(t *testing.T) {
	newDoctor := func() *Doctor {
		return New(fixedSaltConfig(), permissiveDeps(fixedClock()))
	}
	snap := healthySnapshot()

	a, err := json.Marshal(newDoctor().Run(context.Background(), snap))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(newDoctor().Run(context.Background(), snap))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("reports over identical inputs must be byte-identical:\nA=%s\nB=%s", a, b)
	}
}

func TestFindingsCanonicalOrder(t *testing.T) {
	// Even though probes run concurrently and may finish out of order, findings
	// must come out in canonical probe order.
	d := New(fixedSaltConfig(), permissiveDeps(fixedClock()))
	report := d.Run(context.Background(), healthySnapshot())

	last := -1
	for _, f := range report.Findings {
		o := probeOrder(f.Probe)
		if o < last {
			t.Fatalf("findings out of canonical order at %q (order %d < %d)", f.Probe, o, last)
		}
		last = o
	}
	if report.Probes[0].Probe != ProbeCoordinator {
		t.Fatalf("probe outcomes should lead with coordinator, got %q", report.Probes[0].Probe)
	}
}

func TestRunNilContextFailsClosed(t *testing.T) {
	// A nil caller context must never panic inside context.WithTimeout(nil, ...)
	// and must never invent unbounded background work. Run fails closed: every
	// selected probe records a framework error and none actually runs.
	d := New(fixedSaltConfig(), permissiveDeps(fixedClock()),
		WithProbes(staticProbe{id: ProbeCoordinator, code: CodeCoordinatorOK}))
	var nilCtx context.Context
	rep := d.Run(nilCtx, Snapshot{}) // must not panic
	if rep.Summary.OK {
		t.Fatal("a nil-context run must not report OK")
	}
	if rep.Probes[0].Status != StatusError {
		t.Fatalf("expected StatusError for the un-run probe, got %q", rep.Probes[0].Status)
	}
	if !hasCode(rep.Findings, CodeProbeError) {
		t.Fatalf("expected a probe.error finding, got %+v", rep.Findings)
	}
	if hasCode(rep.Findings, CodeCoordinatorOK) {
		t.Fatal("no probe should actually run under a nil context")
	}
}

func TestUnknownProbeIDsFailClosed(t *testing.T) {
	// A Config.Probes made only of unknown ids (typos, removed probes) filters to
	// zero real probes. It must never yield a silent green "nothing ran" report:
	// each distinct unknown id becomes a deterministic probe.error, forcing not-OK.
	cfg := fixedSaltConfig()
	cfg.Probes = []ProbeID{"coordnator", "bogus", "bogus"} // all unknown, one duplicated
	d := New(cfg, permissiveDeps(fixedClock()),
		WithProbes(staticProbe{id: ProbeCoordinator, code: CodeCoordinatorOK}))
	rep := d.Run(context.Background(), Snapshot{})
	if rep.Summary.OK {
		t.Fatal("an all-unknown Config.Probes must not report OK")
	}
	if hasCode(rep.Findings, CodeCoordinatorOK) {
		t.Fatal("no known probe should run when only unknown ids are selected")
	}
	var errCount int
	for _, f := range rep.Findings {
		if f.Code == CodeProbeError {
			errCount++
		}
	}
	if errCount != 2 { // "coordnator" and "bogus"; the duplicate "bogus" is deduped
		t.Fatalf("expected 2 deduped probe.error findings, got %d: %+v", errCount, rep.Findings)
	}
}

func TestUnknownProbeFindingsAreDeterministic(t *testing.T) {
	cfg := fixedSaltConfig()
	cfg.Probes = []ProbeID{"zeta", "alpha", "zeta"}
	d := New(cfg, permissiveDeps(fixedClock()))
	a, err := json.Marshal(d.Run(context.Background(), Snapshot{}))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(d.Run(context.Background(), Snapshot{}))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("unknown-probe framework findings must be byte-deterministic:\nA=%s\nB=%s", a, b)
	}
}

func TestUnknownProbeIDCannotLeakPrivateText(t *testing.T) {
	cfg := fixedSaltConfig()
	cfg.Probes = []ProbeID{"Han-MacBook-Pro/sessionCredentialForHan"}
	out, err := json.Marshal(New(cfg, permissiveDeps(fixedClock())).Run(context.Background(), Snapshot{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"Han-MacBook-Pro", "sessionCredentialForHan"} {
		if strings.Contains(string(out), forbidden) {
			t.Fatalf("unknown probe id leaked %q: %s", forbidden, out)
		}
	}
	if !strings.Contains(string(out), "[redacted:probe:") {
		t.Fatalf("unknown probe id was not replaced by a correlatable token: %s", out)
	}
}

func TestMixedKnownAndUnknownProbeIDs(t *testing.T) {
	// A mix of a known id and an unknown one runs the known probe AND emits a
	// framework error for the unknown, so a healthy known probe can never mask a
	// mis-typed selection into a green summary.
	cfg := fixedSaltConfig()
	cfg.Probes = []ProbeID{ProbeCoordinator, "bogus"}
	d := New(cfg, permissiveDeps(fixedClock()),
		WithProbes(staticProbe{id: ProbeCoordinator, code: CodeCoordinatorOK}))
	rep := d.Run(context.Background(), Snapshot{})
	if !hasCode(rep.Findings, CodeCoordinatorOK) {
		t.Fatal("the known probe in a mixed selection must still run")
	}
	if !hasCode(rep.Findings, CodeProbeError) {
		t.Fatal("the unknown id in a mixed selection must produce a probe.error")
	}
	if rep.Summary.OK {
		t.Fatal("any unknown id must force a not-OK summary even alongside a healthy known probe")
	}
}

func TestNoRunnableProbesFailsClosed(t *testing.T) {
	// A Doctor built with WithProbes() and no probes, and an empty Config.Probes,
	// selects zero probes. That must never read as a silent green "nothing ran"
	// pass: it emits one deterministic framework probe.error and runs nothing.
	d := New(fixedSaltConfig(), permissiveDeps(fixedClock()), WithProbes())

	rep := d.Run(context.Background(), Snapshot{})
	if rep.Summary.OK {
		t.Fatal("a run with zero probes must not report OK")
	}
	if !hasCode(rep.Findings, CodeProbeError) {
		t.Fatalf("expected a framework probe.error, got %+v", rep.Findings)
	}
	if len(rep.Probes) != 1 || rep.Probes[0].Status != StatusError || rep.Probes[0].Probe != ProbeFramework {
		t.Fatalf("expected a single framework-error outcome, got %+v", rep.Probes)
	}

	// The same must hold under a nil context: no panic, still not green.
	var nilCtx context.Context
	nrep := d.Run(nilCtx, Snapshot{})
	if nrep.Summary.OK || !hasCode(nrep.Findings, CodeProbeError) {
		t.Fatalf("zero probes under a nil context must also fail closed, got OK=%v findings=%+v",
			nrep.Summary.OK, nrep.Findings)
	}

	// Diagnose funnels through the same guard and still returns a dry-run plan.
	report, plan := d.Diagnose(context.Background(), Snapshot{})
	if report.Summary.OK || !plan.DryRun || len(plan.Repairs) != 0 {
		t.Fatalf("zero-probe Diagnose must be not-OK with an empty dry-run plan, got OK=%v dry=%v repairs=%d",
			report.Summary.OK, plan.DryRun, len(plan.Repairs))
	}
}

func TestConfiguredSubsetRunsExactlyThatSubset(t *testing.T) {
	// A Config.Probes of only known ids preserves the subset behaviour: exactly
	// those probes run, no framework error is raised, and a healthy subset is OK.
	cfg := fixedSaltConfig()
	cfg.Probes = []ProbeID{ProbeCoordinator}
	d := New(cfg, permissiveDeps(fixedClock()),
		WithProbes(
			staticProbe{id: ProbeCoordinator, code: CodeCoordinatorOK},
			staticProbe{id: ProbeRelay, code: CodeRelayOK},
		))
	rep := d.Run(context.Background(), Snapshot{})
	if len(rep.Probes) != 1 || rep.Probes[0].Probe != ProbeCoordinator {
		t.Fatalf("only the selected coordinator probe should run, got %+v", rep.Probes)
	}
	if hasCode(rep.Findings, CodeProbeError) {
		t.Fatalf("a valid configured subset must not produce framework errors, got %+v", rep.Findings)
	}
	if !rep.Summary.OK {
		t.Fatalf("a healthy configured subset must report OK, got %+v", rep.Findings)
	}
}

func TestDiagnoseNilContextFailsClosed(t *testing.T) {
	// Diagnose funnels through the same guard: it returns a not-OK report and a
	// dry-run plan with no repairs (framework-error findings map to no action).
	d := New(fixedSaltConfig(), permissiveDeps(fixedClock()))
	var nilCtx context.Context
	report, plan := d.Diagnose(nilCtx, capableSnap()) // must not panic
	if report.Summary.OK {
		t.Fatal("a nil-context diagnose must not report OK")
	}
	if !hasCode(report.Findings, CodeProbeError) {
		t.Fatalf("expected probe.error findings, got %+v", report.Findings)
	}
	if !plan.DryRun {
		t.Fatal("Diagnose must always return a dry-run plan")
	}
	if len(plan.Repairs) != 0 {
		t.Fatalf("framework-error findings must map to no repairs, got %+v", plan.Repairs)
	}
}

func TestExecutePlanNilContextIsSafe(t *testing.T) {
	// The mutating entry point must also refuse a nil context without invoking the
	// executor or panicking.
	d := New(fixedSaltConfig(), permissiveDeps(fixedClock()))
	plan := Plan(planEnv(capableSnap()), findingsWith(CodeDNSTimeout))
	exec := &fakeExecutor{}
	var nilCtx context.Context
	rep := d.ExecutePlan(nilCtx, capableSnap(), plan, exec) // must not panic
	for _, r := range rep.Repairs {
		if r.Status != RepairSkipped || !strings.Contains(r.Error, "nil context") {
			t.Fatalf("nil context must skip every repair, got %q / %q", r.Status, r.Error)
		}
	}
	if len(exec.applied) != 0 || len(exec.captured) != 0 {
		t.Fatal("a nil-context ExecutePlan must not touch the executor")
	}
}

func TestNoGoroutineLeakAfterTimeouts(t *testing.T) {
	base := runtime.NumGoroutine()
	cfg := fixedSaltConfig()
	cfg.ProbeTimeout = 20 * time.Millisecond
	for i := 0; i < 20; i++ {
		d := New(cfg, permissiveDeps(fixedClock()), WithProbes(blockingProbe{id: ProbeCoordinator}))
		_ = d.Run(context.Background(), Snapshot{})
	}
	// Blocking probes exit when their context is cancelled; give them a moment
	// and confirm goroutines settle back near the baseline.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= base+5 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines did not settle: base=%d now=%d", base, runtime.NumGoroutine())
}

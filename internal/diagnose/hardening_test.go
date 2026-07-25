package diagnose

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file holds the security/correctness regression tests for the diagnose
// hardening pass: bounded orphan goroutines, key redaction with collision
// handling, tamper-proof repair execution, execution-time precondition
// re-evaluation, finite detached rollback, and the crypto/rand fallback salt.

// --- issue 1: bounded orphan goroutines --------------------------------------

// hostileProbe ignores its context entirely and blocks until release is closed.
// It models a probe that will not honour cancellation, so runOne must stop
// waiting for it without letting repeated timeouts leak goroutines without bound.
type hostileProbe struct {
	id      ProbeID
	release chan struct{}
}

func (h hostileProbe) ID() ProbeID { return h.id }
func (h hostileProbe) Run(ctx context.Context, env *Env) ProbeResult {
	<-h.release // deliberately ignores ctx
	return ProbeResult{Probe: h.id}
}

func TestHostileProbesCannotExceedGoroutineBound(t *testing.T) {
	// Shrink this Doctor's own limiter so a handful of stuck orphans exhaust it,
	// instead of a thousand. The limiter is per-Doctor and immutable, so nothing
	// here mutates a package global that a concurrent Doctor run could race on.
	const bound = 3
	release := make(chan struct{})
	defer close(release) // let every stranded orphan exit when the test ends

	// An already-cancelled context makes runOne stop waiting immediately, with no
	// sleeps: each Run strands exactly one hostile goroutine holding one slot.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d := New(fixedSaltConfig(), permissiveDeps(fixedClock()),
		WithProbes(hostileProbe{id: ProbeCoordinator, release: release}),
		withProbeLimit(bound))

	// Exhaust the budget: `bound` runs strand `bound` orphans.
	for i := 0; i < bound; i++ {
		rep := d.Run(ctx, Snapshot{})
		if rep.Probes[0].Status != StatusTimeout {
			t.Fatalf("run %d: expected the cancelled run to time out, got %q", i, rep.Probes[0].Status)
		}
	}

	// The budget is now full of stuck orphans. Every further run must be refused
	// deterministically rather than spawn another goroutine — this is the bound.
	for i := 0; i < 5; i++ {
		rep := d.Run(ctx, Snapshot{})
		if rep.Probes[0].Status != StatusError {
			t.Fatalf("over-budget run %d: expected StatusError, got %q", i, rep.Probes[0].Status)
		}
		if !hasCode(rep.Findings, CodeProbeError) {
			t.Fatalf("over-budget run %d: expected a probe.error finding, got %+v", i, rep.Findings)
		}
	}
}

func TestWellBehavedProbesRunConcurrentlyUnderBound(t *testing.T) {
	// With headroom in the budget, ordinary concurrent probes must all run: a
	// well-behaved probe releases its slot as soon as it returns. The default cap
	// (64) is comfortably above this test's peak of 8 runs x 3 probes = 24 live
	// goroutines, so no well-behaved probe is ever turned away. The limiter is
	// per-Doctor, so these 8 concurrent Runs share one Doctor's immutable budget
	// with no package-global mutation to race on.
	d := New(fixedSaltConfig(), permissiveDeps(fixedClock()),
		WithProbes(
			staticProbe{id: ProbeRelay, code: CodeRelayOK},
			staticProbe{id: ProbeDNS, code: CodeDNSOK},
			staticProbe{id: ProbeMedia, code: CodeMediaOK},
		),
	)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rep := d.Run(context.Background(), Snapshot{})
			for _, c := range []Code{CodeRelayOK, CodeDNSOK, CodeMediaOK} {
				if !hasCode(rep.Findings, c) {
					t.Errorf("expected %q under a bounded but sufficient budget, got %+v", c, rep.Findings)
				}
			}
		}()
	}
	wg.Wait()
}

// --- issue 2: false-safe context race in runOne ------------------------------

// deadlineEmptyProbe returns an empty, would-be-"completed" result the instant
// its context is done. It models a probe that bails out the moment its deadline
// fires without producing any finding — exactly the shape that must never be
// stamped StatusCompleted, which would read as a clean pass for a check that
// never actually ran.
type deadlineEmptyProbe struct{ id ProbeID }

func (p deadlineEmptyProbe) ID() ProbeID { return p.id }
func (p deadlineEmptyProbe) Run(ctx context.Context, _ *Env) ProbeResult {
	<-ctx.Done()
	return ProbeResult{Probe: p.id} // empty; unset Status would default to completed
}

func TestExpiredContextNeverCompletesEmpty(t *testing.T) {
	cfg := fixedSaltConfig()
	cfg.ProbeTimeout = time.Millisecond // tiny, so the return and the deadline race
	d := New(cfg, permissiveDeps(fixedClock()), WithProbes(deadlineEmptyProbe{id: ProbeCoordinator}))

	// Repeat many times to exercise the select's arbitrary choice between the
	// ready result channel and the already-expired context. Whichever branch wins,
	// the outcome must be a framework timeout with a probe.timeout finding — never
	// a false-safe StatusCompleted with zero findings.
	for i := 0; i < 400; i++ {
		rep := d.Run(context.Background(), Snapshot{})
		out := rep.Probes[0]
		if out.Status == StatusCompleted {
			t.Fatalf("iter %d: expired-context probe stamped completed (false-safe), findings=%d", i, out.FindingCount)
		}
		if out.Status != StatusTimeout {
			t.Fatalf("iter %d: expected StatusTimeout, got %q", i, out.Status)
		}
		if !hasCode(rep.Findings, CodeProbeTimeout) {
			t.Fatalf("iter %d: expected a probe.timeout finding, got %+v", i, rep.Findings)
		}
	}
}

// --- issue 3: key redaction + deterministic collision handling ---------------

func TestRedactJSONRedactsKeys(t *testing.T) {
	r := NewRedactor([]byte("salt"), "rm-authkey-longsecret")
	doc := map[string]any{
		"rm-authkey-longsecret": "v1", // a registered secret used as a key
		"192.168.1.9":           "v2", // an IP used as a key
		"plainkey":              "v3", // ordinary key, must be preserved
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.RedactJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, absent := range []string{"rm-authkey-longsecret", "192.168.1.9"} {
		if strings.Contains(s, absent) {
			t.Errorf("sensitive key %q leaked into %q", absent, s)
		}
	}
	if !strings.Contains(s, "plainkey") {
		t.Errorf("non-sensitive key should be preserved: %q", s)
	}
	// No value may be dropped when keys are rewritten.
	for _, v := range []string{"v1", "v2", "v3"} {
		if !strings.Contains(s, v) {
			t.Errorf("value %q dropped during key redaction: %q", v, s)
		}
	}
}

func TestRedactJSONKeyCollisionKeepsBothValues(t *testing.T) {
	r := NewRedactor([]byte("salt"))
	addr := "10.0.0.7"
	// A hostile document supplies both a real address key and a second key that
	// is already that address's redacted placeholder. Both keys redact to the
	// same string, so without deterministic disambiguation one value would
	// silently overwrite the other.
	mimic := r.String(addr)
	if mimic == addr {
		t.Fatal("test precondition: address should redact to a placeholder")
	}
	doc := map[string]any{addr: "real", mimic: "mimic"}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.RedactJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("redacted output is not valid JSON: %v", err)
	}
	if len(back) != 2 {
		t.Fatalf("collision collapsed two keys into %d: %s", len(back), out)
	}
	s := string(out)
	if strings.Contains(s, addr) {
		t.Errorf("raw address key leaked: %s", s)
	}
	if !strings.Contains(s, `"real"`) || !strings.Contains(s, `"mimic"`) {
		t.Errorf("a value was silently overwritten by a colliding key: %s", s)
	}
	// Collision handling must be deterministic across repeated runs.
	out2, err := r.RedactJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(out2) {
		t.Errorf("collision handling must be deterministic:\n%s\n%s", out, out2)
	}
}

// --- issue 4: tamper-proof repair execution ----------------------------------

func TestExecuteRejectsMaliciousParams(t *testing.T) {
	env := planEnv(capableSnap())
	// Allowed action, allowed op, but tampered parameters: the catalogue sets the
	// MTU to the path-safe 1280; the attacker asks for a value that would break
	// connectivity.
	plan := RepairPlan{DryRun: true, Repairs: []PlannedRepair{{
		Action:     ActionLowerMTU,
		Applicable: true,
		Snapshots:  []SnapshotRequest{{Kind: "mtu"}},
		Apply:      []Step{{Op: OpSetMTU, Params: map[string]string{"mtu": "1"}}},
		Rollback:   []Step{{Op: OpSetMTU, Params: map[string]string{paramFromSnapshot: "mtu"}}},
	}}}
	exec := &fakeExecutor{}
	rep := Execute(context.Background(), env, plan, exec)
	if rep.Repairs[0].Status != RepairSkipped {
		t.Fatalf("tampered params must be rejected, got %q", rep.Repairs[0].Status)
	}
	if !strings.Contains(rep.Repairs[0].Error, "do not match the authoritative recipe") {
		t.Fatalf("error should cite the recipe mismatch, got %q", rep.Repairs[0].Error)
	}
	if len(exec.applied) != 0 || len(exec.captured) != 0 {
		t.Fatal("a rejected repair must not capture or apply anything")
	}
}

func TestExecuteRejectsSubstitutedRecipe(t *testing.T) {
	env := planEnv(capableSnap())
	// Allowed action id, but the steps are a different (also-allowed) op: an
	// attacker substituting a destructive recipe under a benign action's name.
	plan := RepairPlan{DryRun: true, Repairs: []PlannedRepair{{
		Action:     ActionFlushDNS, // catalogue: idempotent, Apply=[dns.flush_cache]
		Applicable: true,
		Apply:      []Step{{Op: OpRestartWireGuard}}, // substituted, still allowlisted
	}}}
	exec := &fakeExecutor{}
	rep := Execute(context.Background(), env, plan, exec)
	if rep.Repairs[0].Status != RepairSkipped {
		t.Fatalf("substituted recipe must be rejected, got %q", rep.Repairs[0].Status)
	}
	if !strings.Contains(rep.Repairs[0].Error, "authoritative recipe") {
		t.Fatalf("error should cite the recipe mismatch, got %q", rep.Repairs[0].Error)
	}
	if len(exec.applied) != 0 {
		t.Fatal("nothing should be applied for a substituted recipe")
	}
}

func TestExecuteRejectsDuplicateActions(t *testing.T) {
	env := planEnv(capableSnap())
	// Two copies of the same valid, state-changing repair. The first applies; the
	// duplicate is rejected so the repair cannot run twice against one snapshot.
	one := Plan(env, findingsWith(CodeRoutesDefaultMissing)).Repairs[0]
	plan := RepairPlan{DryRun: true, Repairs: []PlannedRepair{one, one}}
	exec := &fakeExecutor{}
	rep := Execute(context.Background(), env, plan, exec)
	if len(rep.Repairs) != 2 {
		t.Fatalf("expected two execution records, got %d", len(rep.Repairs))
	}
	if rep.Repairs[0].Status != RepairApplied {
		t.Fatalf("first copy should apply, got %q (%s)", rep.Repairs[0].Status, rep.Repairs[0].Error)
	}
	if rep.Repairs[1].Status != RepairSkipped || !strings.Contains(rep.Repairs[1].Error, "duplicate") {
		t.Fatalf("duplicate should be skipped, got %q / %q", rep.Repairs[1].Status, rep.Repairs[1].Error)
	}
}

// --- issue 5: execution-time precondition re-evaluation (TOCTOU) -------------

func TestExecuteReevaluatesPreconditionsAtRuntime(t *testing.T) {
	// Plan while the prerequisite holds, so the repair is marked Applicable.
	plan := Plan(planEnv(capableSnap()), findingsWith(CodeMTUSuboptimal)) // lower-mtu needs WireGuard
	pr, ok := plannedFor(plan, ActionLowerMTU)
	if !ok || !pr.Applicable {
		t.Fatalf("precondition: lower-mtu should plan as applicable, got %+v", pr)
	}
	// Between plan and execute the WireGuard interface disappears. Execute must
	// re-check against this trusted env and refuse, despite the plan's stale
	// Applicable==true.
	execEnv := planEnv(Snapshot{}) // no WireGuard
	exec := &fakeExecutor{}
	rep := Execute(context.Background(), execEnv, plan, exec)
	pe, _ := execFor(rep, ActionLowerMTU)
	if pe.Status != RepairSkipped {
		t.Fatalf("stale-applicable repair must be skipped at execution time, got %q", pe.Status)
	}
	if !strings.Contains(pe.Error, "precondition") {
		t.Fatalf("error should cite the failed precondition, got %q", pe.Error)
	}
	if len(exec.applied) != 0 || len(exec.captured) != 0 {
		t.Fatal("a repair failing its live precondition must not touch the system")
	}
}

func TestExecutePlanReevaluatesAgainstFreshSnapshot(t *testing.T) {
	// Plan against a capable snapshot so lower-mtu is applicable, then execute via
	// the Doctor entry point against a fresh snapshot that no longer satisfies the
	// precondition. The stale Applicable bit must be ignored.
	d := New(fixedSaltConfig(), permissiveDeps(fixedClock()))
	plan := Plan(planEnv(capableSnap()), findingsWith(CodeMTUSuboptimal))
	if pr, ok := plannedFor(plan, ActionLowerMTU); !ok || !pr.Applicable {
		t.Fatalf("precondition: lower-mtu should plan as applicable, got %+v", pr)
	}
	exec := &fakeExecutor{}
	rep := d.ExecutePlan(context.Background(), Snapshot{}, plan, exec) // no WireGuard now
	pe, _ := execFor(rep, ActionLowerMTU)
	if pe.Status != RepairSkipped || !strings.Contains(pe.Error, "precondition") {
		t.Fatalf("ExecutePlan must re-evaluate preconditions against the fresh snapshot, got %q / %q", pe.Status, pe.Error)
	}
	if len(exec.applied) != 0 {
		t.Fatal("nothing should be applied when the live precondition fails")
	}
}

// --- issue 6: finite detached rollback, nil safety ---------------------------

// deadlineRollbackExecutor fails a chosen apply op to trigger rollback, then, on
// chosen rollback ops, blocks ignoring normal cancellation and only returns when
// its context deadline fires. It models an Executor that honours deadlines but
// not caller cancellation.
type deadlineRollbackExecutor struct {
	applyFail RepairOp
	blockOn   map[RepairOp]bool
}

func (e *deadlineRollbackExecutor) CaptureSnapshot(ctx context.Context, req SnapshotRequest) (SnapshotData, error) {
	return SnapshotData{Kind: req.Kind}, nil
}

func (e *deadlineRollbackExecutor) Apply(ctx context.Context, step Step, _ []SnapshotData) error {
	if step.Op == e.applyFail {
		return errors.New("apply failed")
	}
	if e.blockOn[step.Op] {
		<-ctx.Done() // ignores normal cancellation; only a deadline frees it
		return ctx.Err()
	}
	return nil
}

func (e *deadlineRollbackExecutor) CheckPostcondition(context.Context, PostconditionID, []SnapshotData) (bool, error) {
	return true, nil
}

func TestRollbackUsesFiniteDetachedTimeout(t *testing.T) {
	cfg := fixedSaltConfig()
	cfg.RollbackTimeout = 50 * time.Millisecond
	env := envWith(capableSnap(), Deps{Clock: fixedClock()}, cfg)
	plan := Plan(env, findingsWith(CodeRoutesDefaultMissing)) // reapply-routes
	exec := &deadlineRollbackExecutor{
		applyFail: OpReapplyRoutes,
		blockOn:   map[RepairOp]bool{OpRestoreRoutes: true},
	}

	// The caller's context is NOT cancelled; the rollback still returns because
	// its own finite, detached deadline fires — proving it neither inherits the
	// caller's (non-)cancellation nor hangs forever. Because the rollback step
	// itself timed out, the prior state was NOT restored, so the status must be
	// the distinct rollback_failed rather than a "restored" rolled_back.
	rep := Execute(context.Background(), env, plan, exec)
	pr, _ := execFor(rep, ActionReapplyRoutes)
	if pr.Status != RepairRollbackFailed {
		t.Fatalf("a timed-out rollback must report rollback_failed, got %q", pr.Status)
	}
	if len(pr.RolledBack) != 1 || pr.RolledBack[0].OK {
		t.Fatalf("rollback step should be recorded as failed, got %+v", pr.RolledBack)
	}
	if !strings.Contains(pr.RolledBack[0].Error, "deadline exceeded") {
		t.Fatalf("rollback should end on its detached deadline, got %q", pr.RolledBack[0].Error)
	}
	// The primary apply error must be preserved alongside the rollback failure.
	if !strings.Contains(pr.Error, "apply failed") || !strings.Contains(pr.Error, "rollback did not complete") {
		t.Fatalf("error should preserve the primary apply failure and the rollback failure, got %q", pr.Error)
	}
}

func TestExecuteNilExecutorIsSafe(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeDNSTimeout))
	rep := Execute(context.Background(), env, plan, nil) // must not panic
	if len(rep.Repairs) == 0 {
		t.Fatal("expected an execution record")
	}
	for _, r := range rep.Repairs {
		if r.Status != RepairSkipped {
			t.Fatalf("nil executor should skip every repair, got %q", r.Status)
		}
		if !strings.Contains(r.Error, "executor") {
			t.Fatalf("error should mention the missing executor, got %q", r.Error)
		}
	}
}

func TestExecuteNilContextIsSafe(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeDNSTimeout)) // flush-dns, idempotent
	exec := &fakeExecutor{}
	var nilCtx context.Context
	rep := Execute(nilCtx, env, plan, exec) // nil context must be refused, not run
	pr, ok := execFor(rep, ActionFlushDNS)
	if !ok || pr.Status != RepairSkipped {
		t.Fatalf("nil context should skip the repair, got %+v", rep.Repairs)
	}
	if !strings.Contains(pr.Error, "nil context") {
		t.Fatalf("error should cite the nil context, got %q", pr.Error)
	}
	// The executor must never be invoked for a nil-context repair.
	if len(exec.captured) != 0 || len(exec.applied) != 0 || len(exec.checked) != 0 {
		t.Fatalf("nil context must not invoke the executor, got captured=%v applied=%v checked=%v",
			exec.captured, exec.applied, exec.checked)
	}
}

// --- issue 7: crypto/rand failure fails closed, never a predictable salt ------

// hmacFP matches a value-derived HMAC fingerprint placeholder, e.g.
// "[redacted:host:1a2b3c4d5e6f]". Its presence in fail-closed output would mean a
// predictable, dictionary-verifiable fingerprint leaked.
var hmacFP = regexp.MustCompile(`\[redacted:[a-z0-9-]+:[0-9a-f]{12}\]`)

func TestRandomSaltReportsEntropyFailure(t *testing.T) {
	old := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	defer func() { randRead = old }()

	if _, ok := randomSalt(); ok {
		t.Fatal("randomSalt must report failure when crypto/rand fails, not fabricate a salt")
	}
	if salt, ok := func() ([]byte, bool) { randRead = old; return randomSalt() }(); !ok || len(salt) != 16 {
		t.Fatalf("randomSalt must return a 16-byte salt when entropy is available, got ok=%v len=%d", ok, len(salt))
	}
}

// TestEntropyFailureSealsRedactor proves that when crypto/rand cannot seed a
// salt, a Doctor fails closed to an opaque redactor: raw values never leak, no
// value-derived HMAC fingerprint is emitted, and two independent reports over the
// same secret cannot be correlated by any per-value tag.
func TestEntropyFailureSealsRedactor(t *testing.T) {
	old := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	defer func() { randRead = old }()

	const secret = "rm-authkey-9f8e7d6c5b4a3210"
	snap := Snapshot{
		Coordinator: Endpoint{Label: "coordinator", Host: "coord.example.net"},
		Secrets:     []string{secret},
	}
	// No fixed salt, so the Doctor must draw entropy — which fails here.
	cfg := DefaultConfig()
	cfg.Probes = []ProbeID{ProbeCoordinator}

	report := func() string {
		d := New(cfg, permissiveDeps(fixedClock()))
		out, err := json.Marshal(d.Run(context.Background(), snap))
		if err != nil {
			t.Fatal(err)
		}
		// Force the secret and host through the redactor directly too, so the
		// assertion does not depend on a probe happening to echo them.
		env := d.newEnv(snap)
		return string(out) + env.Redactor.String("secret "+secret+" host coord.example.net")
	}

	a := report()
	b := report()

	// 1. Raw values never leak (the host is a registered secret, so it too is
	//    scrubbed rather than surviving verbatim).
	for _, raw := range []string{secret, "coord.example.net"} {
		if strings.Contains(a, raw) || strings.Contains(b, raw) {
			t.Fatalf("raw value %q leaked under sealed redaction", raw)
		}
	}
	// 2. No value-derived HMAC fingerprint is emitted in either report, so nothing
	//    is dictionary-verifiable and no per-value tag can correlate a value across
	//    the two independent reports.
	for _, out := range []string{a, b} {
		if m := hmacFP.FindString(out); m != "" {
			t.Fatalf("sealed output must not expose a dictionary-verifiable fingerprint, found %q", m)
		}
	}
	// 3. Values collapse to opaque, value-free markers.
	if !strings.Contains(a, "[redacted:secret]") {
		t.Fatalf("expected opaque sealed placeholders, got %q", a)
	}
}

// TestSealedRedactorNoFingerprint checks the sealed redactor directly: every
// pattern kind collapses to an opaque, value-free marker.
func TestSealedRedactorNoFingerprint(t *testing.T) {
	r := newSealedRedactor("rm-shortpin-secret")
	in := "peer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= at 10.0.0.5 via https://user:pw@h.example.net/p?q=1 rm-shortpin-secret"
	out := r.String(in)
	if m := hmacFP.FindString(out); m != "" {
		t.Fatalf("sealed redactor must not emit an HMAC fingerprint, found %q in %q", m, out)
	}
	for _, raw := range []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "10.0.0.5", "h.example.net", "rm-shortpin-secret"} {
		if strings.Contains(out, raw) {
			t.Fatalf("sealed redactor leaked %q in %q", raw, out)
		}
	}
}

package diagnose

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func findingsWith(codes ...Code) []Finding {
	var fs []Finding
	for _, c := range codes {
		fs = append(fs, Finding{Code: c, Severity: c.DefaultSeverity(), Probe: ProbeCoordinator, Summary: string(c)})
	}
	return fs
}

// capableSnap satisfies every repair precondition, so applicability reflects the
// findings, not missing prerequisites. The link and observed path MTU are set
// well above the 1280 floor so the MTU-lowering repair's path-safety
// precondition (preMTULowerSafe) is satisfied too.
func capableSnap() Snapshot {
	return Snapshot{
		Coordinator:     Endpoint{Host: "c.example.net"},
		Relays:          []Endpoint{{Host: "r.example.net"}},
		Exit:            &ExitState{PeerPublicKey: "cGVlcg=="},
		WireGuard:       WireGuardState{Interface: "utun7", Up: true, LinkMTU: 1500},
		DNS:             DNSState{Servers: addrs("100.100.100.100")},
		ObservedPathMTU: 1400,
	}
}

func planEnv(snap Snapshot) *Env {
	return envWith(snap, Deps{Clock: fixedClock()}, fixedSaltConfig())
}

func plannedFor(p RepairPlan, id RepairActionID) (PlannedRepair, bool) {
	for _, r := range p.Repairs {
		if r.Action == id {
			return r, true
		}
	}
	return PlannedRepair{}, false
}

func TestCatalogIsValid(t *testing.T) {
	if err := validateCatalog(repairCatalog); err != nil {
		t.Fatalf("shipped catalog is invalid: %v", err)
	}
}

func TestCatalogRollbackCompleteness(t *testing.T) {
	for _, a := range repairCatalog {
		captured := map[string]bool{}
		for _, s := range a.Snapshots {
			captured[s.Kind] = true
		}
		if a.Idempotent {
			if len(a.Rollback) != 0 || len(a.Snapshots) != 0 {
				t.Errorf("%s: idempotent action must not carry rollback/snapshots", a.ID)
			}
			continue
		}
		if len(a.Snapshots) == 0 || len(a.Rollback) == 0 {
			t.Errorf("%s: state-changing action must snapshot and roll back", a.ID)
		}
		// Every rollback step that reads a snapshot must reference a captured one.
		for _, step := range a.Rollback {
			if k := step.Params[paramFromSnapshot]; k != "" && !captured[k] {
				t.Errorf("%s: rollback reads uncaptured snapshot %q", a.ID, k)
			}
		}
	}
}

func TestValidateCatalogRejectsBadEntries(t *testing.T) {
	cases := map[string][]RepairAction{
		"non-allowlisted action":        {{ID: "bogus", Fixes: []Code{CodeDNSOK}, Idempotent: true, Apply: []Step{{Op: OpFlushDNS}}}},
		"unknown code":                  {{ID: ActionFlushDNS, Fixes: []Code{"no.such_code"}, Idempotent: true, Apply: []Step{{Op: OpFlushDNS}}}},
		"non-allowlisted op":            {{ID: ActionFlushDNS, Fixes: []Code{CodeDNSOK}, Idempotent: true, Apply: []Step{{Op: "evil.rm"}}}},
		"missing rollback":              {{ID: ActionLowerMTU, Fixes: []Code{CodeMTUTooLow}, Snapshots: []SnapshotRequest{{Kind: "mtu"}}, Apply: []Step{{Op: OpSetMTU}}, Postconditions: []PostconditionID{PostMTUPathSafe}}},
		"idempotent with rollback":      {{ID: ActionFlushDNS, Fixes: []Code{CodeDNSOK}, Idempotent: true, Apply: []Step{{Op: OpFlushDNS}}, Rollback: []Step{{Op: OpFlushDNS}}, Postconditions: []PostconditionID{PostDNSResolves}}},
		"dangling snapshot ref":         {{ID: ActionLowerMTU, Fixes: []Code{CodeMTUTooLow}, Snapshots: []SnapshotRequest{{Kind: "mtu"}}, Apply: []Step{{Op: OpSetMTU}}, Rollback: []Step{{Op: OpSetMTU, Params: map[string]string{paramFromSnapshot: "nope"}}}, Postconditions: []PostconditionID{PostMTUPathSafe}}},
		"missing postcondition":         {{ID: ActionFlushDNS, Fixes: []Code{CodeDNSOK}, Idempotent: true, Apply: []Step{{Op: OpFlushDNS}}}},
		"non-allowlisted postcondition": {{ID: ActionFlushDNS, Fixes: []Code{CodeDNSOK}, Idempotent: true, Apply: []Step{{Op: OpFlushDNS}}, Postconditions: []PostconditionID{"bogus.check"}}},
		"duplicate postcondition":       {{ID: ActionFlushDNS, Fixes: []Code{CodeDNSOK}, Idempotent: true, Apply: []Step{{Op: OpFlushDNS}}, Postconditions: []PostconditionID{PostDNSResolves, PostDNSResolves}}},
	}
	for name, cat := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validateCatalog(cat); err == nil {
				t.Fatal("expected validation error, got nil")
			}
		})
	}
}

func TestAllowedOp(t *testing.T) {
	if !AllowedOp(OpFlushDNS) {
		t.Fatal("OpFlushDNS should be allowlisted")
	}
	if AllowedOp("evil.rm") {
		t.Fatal("arbitrary op must not be allowlisted")
	}
}

func TestPlanMapsFindingsInCatalogOrder(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeCoordinatorUnreachable, CodeDNSTimeout))
	if !plan.DryRun {
		t.Fatal("Plan must produce a dry run")
	}
	if len(plan.Repairs) != 2 {
		t.Fatalf("expected 2 repairs, got %d", len(plan.Repairs))
	}
	// flush-dns precedes reconnect-coordinator in the catalogue.
	if plan.Repairs[0].Action != ActionFlushDNS || plan.Repairs[1].Action != ActionReconnectCoordinator {
		t.Fatalf("repairs out of catalogue order: %+v", []RepairActionID{plan.Repairs[0].Action, plan.Repairs[1].Action})
	}
}

func TestPlanDedupesActionAndSortsAddresses(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeWireGuardHandshakeStale, CodeWireGuardInterfaceDown))
	pr, ok := plannedFor(plan, ActionRestartWireGuard)
	if !ok {
		t.Fatal("expected restart-wireguard")
	}
	if len(plan.Repairs) != 1 {
		t.Fatalf("action should appear once, got %d repairs", len(plan.Repairs))
	}
	if len(pr.Addresses) != 2 || pr.Addresses[0] > pr.Addresses[1] {
		t.Fatalf("addresses should be de-duplicated and sorted, got %+v", pr.Addresses)
	}
}

func TestPlanPreconditionGating(t *testing.T) {
	// mtu.suboptimal maps to lower-mtu, which needs a WireGuard interface. Without
	// one, the repair is present but not applicable, with a precondition detail.
	env := planEnv(Snapshot{}) // no WireGuard
	plan := Plan(env, findingsWith(CodeMTUSuboptimal))
	pr, ok := plannedFor(plan, ActionLowerMTU)
	if !ok {
		t.Fatal("expected lower-mtu in the plan")
	}
	if pr.Applicable {
		t.Fatal("lower-mtu must not be applicable without a WireGuard interface")
	}
	if len(pr.Preconditions) == 0 || pr.Preconditions[0].OK {
		t.Fatalf("expected a failing precondition, got %+v", pr.Preconditions)
	}
	if len(plan.Applicable()) != 0 {
		t.Fatal("Applicable() should be empty")
	}
}

func TestPlanDeterministic(t *testing.T) {
	env := planEnv(capableSnap())
	fs := findingsWith(CodeDNSTimeout, CodeRoutesDefaultMissing, CodeCoordinatorUnreachable)
	a, _ := json.Marshal(Plan(env, fs))
	b, _ := json.Marshal(Plan(env, fs))
	if string(a) != string(b) {
		t.Fatalf("plans must be deterministic:\nA=%s\nB=%s", a, b)
	}
}

func TestExecuteApplies(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeExitEgressBlocked)) // rebuild-exit: clear then set
	exec := &fakeExecutor{}
	rep := Execute(context.Background(), env, plan, exec)

	pr, ok := execFor(rep, ActionRebuildExit)
	if !ok || pr.Status != RepairApplied {
		t.Fatalf("expected rebuild-exit applied, got %+v", rep.Repairs)
	}
	if len(exec.captured) != 1 || exec.captured[0] != "exit-selection" {
		t.Fatalf("snapshot should be captured before apply, got %+v", exec.captured)
	}
	wantOps := []RepairOp{OpClearExit, OpSetExit}
	if len(pr.Applied) != 2 || pr.Applied[0].Op != wantOps[0] || pr.Applied[1].Op != wantOps[1] {
		t.Fatalf("apply order wrong, got %+v", pr.Applied)
	}
}

func TestExecuteRollsBackOnApplyFailure(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeRoutesDefaultMissing)) // reapply-routes
	exec := &fakeExecutor{applyFail: OpReapplyRoutes}
	rep := Execute(context.Background(), env, plan, exec)

	pr, _ := execFor(rep, ActionReapplyRoutes)
	if pr.Status != RepairRolledBack {
		t.Fatalf("expected rolled_back, got %q", pr.Status)
	}
	if len(pr.Applied) != 1 || pr.Applied[0].OK {
		t.Fatalf("apply step should be recorded as failed, got %+v", pr.Applied)
	}
	if len(pr.RolledBack) != 1 || pr.RolledBack[0].Op != OpRestoreRoutes || !pr.RolledBack[0].OK {
		t.Fatalf("rollback should restore routes, got %+v", pr.RolledBack)
	}
}

func TestExecuteAbortsWhenSnapshotFails(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeRoutesDefaultMissing))
	exec := &fakeExecutor{snapshotFail: "routes"}
	rep := Execute(context.Background(), env, plan, exec)

	pr, _ := execFor(rep, ActionReapplyRoutes)
	if pr.Status != RepairSnapshotFailed {
		t.Fatalf("expected snapshot_failed, got %q", pr.Status)
	}
	if len(exec.applied) != 0 {
		t.Fatalf("nothing should be applied after a snapshot failure, got %+v", exec.applied)
	}
}

func TestExecuteChecksPostconditionsAfterApply(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeRoutesDefaultMissing)) // reapply-routes
	exec := &fakeExecutor{}                                   // postconditions pass by default
	rep := Execute(context.Background(), env, plan, exec)

	pr, _ := execFor(rep, ActionReapplyRoutes)
	if pr.Status != RepairApplied {
		t.Fatalf("expected applied, got %q (%s)", pr.Status, pr.Error)
	}
	// The recipe's postcondition must actually have been checked before success.
	if len(exec.checked) != 1 || exec.checked[0] != PostDefaultRoutePresent {
		t.Fatalf("expected the route postcondition to be checked, got %+v", exec.checked)
	}
	if len(pr.RolledBack) != 0 {
		t.Fatalf("a satisfied postcondition must not roll back, got %+v", pr.RolledBack)
	}
}

func TestExecuteFailedPostconditionRollsBack(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeRoutesDefaultMissing)) // reapply-routes
	// Apply succeeds, but the route is still not present afterward.
	exec := &fakeExecutor{postFail: PostDefaultRoutePresent}
	rep := Execute(context.Background(), env, plan, exec)

	pr, _ := execFor(rep, ActionReapplyRoutes)
	if pr.Status != RepairPostconditionFailed {
		t.Fatalf("expected postcondition_failed, got %q", pr.Status)
	}
	if !strings.Contains(pr.Error, "postcondition") || !strings.Contains(pr.Error, "did not hold") {
		t.Fatalf("error should cite the unmet postcondition, got %q", pr.Error)
	}
	// The apply step succeeded, so the full rollback must have run to restore state.
	if len(pr.Applied) != 1 || !pr.Applied[0].OK {
		t.Fatalf("apply step should be recorded as succeeded, got %+v", pr.Applied)
	}
	if len(pr.RolledBack) != 1 || pr.RolledBack[0].Op != OpRestoreRoutes || !pr.RolledBack[0].OK {
		t.Fatalf("a failed postcondition must trigger the complete rollback, got %+v", pr.RolledBack)
	}
}

func TestExecutePostconditionTimeoutRollsBack(t *testing.T) {
	cfg := fixedSaltConfig()
	cfg.ApplyTimeout = 50 * time.Millisecond // finite bound on the apply/postcondition phase
	env := envWith(capableSnap(), Deps{Clock: fixedClock()}, cfg)
	plan := Plan(env, findingsWith(CodeRoutesDefaultMissing)) // reapply-routes
	// The postcondition check blocks until its context deadline fires.
	exec := &fakeExecutor{postBlock: PostDefaultRoutePresent}

	// The caller's context is NOT cancelled; the check still returns because the
	// finite execution context (ApplyTimeout) fires, proving Background cannot
	// wedge the repair forever.
	rep := Execute(context.Background(), env, plan, exec)
	pr, _ := execFor(rep, ActionReapplyRoutes)
	if pr.Status != RepairPostconditionFailed {
		t.Fatalf("a postcondition that cannot be verified in time must fail closed, got %q", pr.Status)
	}
	if !strings.Contains(pr.Error, "could not be verified") {
		t.Fatalf("error should cite the unverifiable postcondition, got %q", pr.Error)
	}
	if len(pr.RolledBack) != 1 || pr.RolledBack[0].Op != OpRestoreRoutes {
		t.Fatalf("a timed-out postcondition must trigger rollback, got %+v", pr.RolledBack)
	}
}

func TestExecuteRejectsTamperedPostconditions(t *testing.T) {
	env := planEnv(capableSnap())
	// Valid action, ops, snapshots and steps, but a substituted (still allowlisted)
	// postcondition: the recipe verifies PostDefaultRoutePresent; the plan asks for
	// a different check that would let a broken repair report success.
	plan := RepairPlan{DryRun: true, Repairs: []PlannedRepair{{
		Action:         ActionReapplyRoutes,
		Applicable:     true,
		Snapshots:      []SnapshotRequest{{Kind: "routes"}},
		Apply:          []Step{{Op: OpReapplyRoutes}},
		Rollback:       []Step{{Op: OpRestoreRoutes, Params: map[string]string{paramFromSnapshot: "routes"}}},
		Postconditions: []PostconditionID{PostWireGuardUp}, // tampered
	}}}
	exec := &fakeExecutor{}
	rep := Execute(context.Background(), env, plan, exec)
	if rep.Repairs[0].Status != RepairSkipped {
		t.Fatalf("tampered postconditions must be rejected, got %q", rep.Repairs[0].Status)
	}
	if !strings.Contains(rep.Repairs[0].Error, "postconditions do not match") {
		t.Fatalf("error should cite the postcondition mismatch, got %q", rep.Repairs[0].Error)
	}
	if len(exec.applied) != 0 || len(exec.captured) != 0 || len(exec.checked) != 0 {
		t.Fatal("a rejected plan must not capture, apply, or check anything")
	}
}

func TestExecuteOmittedPostconditionsRejected(t *testing.T) {
	env := planEnv(capableSnap())
	// A plan that drops the recipe's postconditions entirely must not slip through:
	// otherwise a tampered plan could disable success verification.
	plan := RepairPlan{DryRun: true, Repairs: []PlannedRepair{{
		Action:     ActionReapplyRoutes,
		Applicable: true,
		Snapshots:  []SnapshotRequest{{Kind: "routes"}},
		Apply:      []Step{{Op: OpReapplyRoutes}},
		Rollback:   []Step{{Op: OpRestoreRoutes, Params: map[string]string{paramFromSnapshot: "routes"}}},
		// Postconditions omitted.
	}}}
	exec := &fakeExecutor{}
	rep := Execute(context.Background(), env, plan, exec)
	if rep.Repairs[0].Status != RepairSkipped || !strings.Contains(rep.Repairs[0].Error, "postconditions do not match") {
		t.Fatalf("omitted postconditions must be rejected, got %q / %q", rep.Repairs[0].Status, rep.Repairs[0].Error)
	}
}

func TestExecuteIdempotentFailedPostconditionIsUncertain(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeDNSTimeout)) // flush-dns, idempotent
	// The idempotent repair applies (a mutation happened), but its postcondition
	// does not hold. It declares no rollback recipe, so nothing can prove the prior
	// state was restored: the outcome must be the explicit uncertain status, NEVER
	// postcondition_failed (which asserts restoration). It still records no rollback
	// steps and the applied step, but the caller is told to intervene manually.
	exec := &fakeExecutor{postFail: PostDNSResolves}
	rep := Execute(context.Background(), env, plan, exec)

	pr, _ := execFor(rep, ActionFlushDNS)
	if pr.Status != RepairUncertain {
		t.Fatalf("expected uncertain, got %q", pr.Status)
	}
	if pr.Status == RepairPostconditionFailed || pr.Status == RepairRolledBack {
		t.Fatalf("a no-rollback action must never claim restoration, got %q", pr.Status)
	}
	if !strings.Contains(pr.Error, "manual intervention") || !strings.Contains(pr.Error, "postcondition") {
		t.Fatalf("error should cite the unmet postcondition and manual intervention, got %q", pr.Error)
	}
	if len(pr.Applied) != 1 || pr.Applied[0].Op != OpFlushDNS || !pr.Applied[0].OK {
		t.Fatalf("the idempotent step should record as applied, got %+v", pr.Applied)
	}
	if len(pr.RolledBack) != 0 {
		t.Fatalf("an idempotent action has nothing to roll back, got %+v", pr.RolledBack)
	}
}

func TestExecuteIdempotentFailedApplyIsUncertain(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeDNSTimeout)) // flush-dns, idempotent
	// The idempotent action's apply itself fails. A mutation was attempted and no
	// rollback recipe exists, so the prior state cannot be proven restored: this
	// must be uncertain, NEVER rolled_back (which would tell a UI "no lasting
	// change"). The apply step is recorded as failed and no rollback runs.
	exec := &fakeExecutor{applyFail: OpFlushDNS}
	rep := Execute(context.Background(), env, plan, exec)

	pr, _ := execFor(rep, ActionFlushDNS)
	if pr.Status != RepairUncertain {
		t.Fatalf("expected uncertain, got %q", pr.Status)
	}
	if pr.Status == RepairRolledBack {
		t.Fatalf("a failed mutation with no rollback must never claim restoration, got %q", pr.Status)
	}
	if !strings.Contains(pr.Error, "manual intervention") {
		t.Fatalf("error should cite manual intervention, got %q", pr.Error)
	}
	if len(pr.Applied) != 1 || pr.Applied[0].Op != OpFlushDNS || pr.Applied[0].OK {
		t.Fatalf("the failed idempotent step should record as not-OK, got %+v", pr.Applied)
	}
	if len(pr.RolledBack) != 0 {
		t.Fatalf("an idempotent action has nothing to roll back, got %+v", pr.RolledBack)
	}
}

func TestExecuteSkipsInapplicable(t *testing.T) {
	env := planEnv(Snapshot{}) // no WireGuard, so lower-mtu is not applicable
	plan := Plan(env, findingsWith(CodeMTUSuboptimal))
	exec := &fakeExecutor{}
	rep := Execute(context.Background(), env, plan, exec)

	pr, _ := execFor(rep, ActionLowerMTU)
	if pr.Status != RepairSkipped {
		t.Fatalf("expected skipped, got %q", pr.Status)
	}
	if len(exec.captured) != 0 || len(exec.applied) != 0 {
		t.Fatal("an inapplicable repair must not capture or apply anything")
	}
}

func TestExecuteRefusesNonAllowlistedOp(t *testing.T) {
	env := planEnv(capableSnap())
	plan := RepairPlan{DryRun: true, Repairs: []PlannedRepair{{
		Action:     ActionFlushDNS,
		Applicable: true,
		Apply:      []Step{{Op: "evil.rm"}},
	}}}
	exec := &fakeExecutor{}
	rep := Execute(context.Background(), env, plan, exec)
	if rep.Repairs[0].Status != RepairSkipped {
		t.Fatalf("expected skipped for a non-allowlisted op, got %q", rep.Repairs[0].Status)
	}
	if !strings.Contains(rep.Repairs[0].Error, "non-allowlisted") {
		t.Fatalf("error should mention the allowlist, got %q", rep.Repairs[0].Error)
	}
	if len(exec.applied) != 0 {
		t.Fatal("no step should be applied for a rejected plan")
	}
}

func TestExecuteRollbackRunsUnderCancelledContext(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeRoutesDefaultMissing))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A mutation IS attempted: the first apply step runs, cancels the caller's
	// context mid-flight, then fails — forcing a rollback. The rollback must still
	// run under a detached, non-cancelled context so cleanup completes even though
	// the caller has since given up. (A context cancelled *before* the first apply
	// call attempts no mutation and must NOT roll back — see
	// TestExecuteContextExpiresBeforeFirstApplyRollsBackNothing.)
	exec := &fakeExecutor{applyFail: OpReapplyRoutes, onApply: cancel}
	rep := Execute(ctx, env, plan, exec)

	pr, _ := execFor(rep, ActionReapplyRoutes)
	if pr.Status != RepairRolledBack {
		t.Fatalf("a failed apply should roll back, got %q (%s)", pr.Status, pr.Error)
	}
	if len(pr.Applied) != 1 || pr.Applied[0].OK {
		t.Fatalf("the forward apply must have been attempted and failed, got %+v", pr.Applied)
	}
	if len(pr.RolledBack) == 0 {
		t.Fatal("rollback steps should have run")
	}
	if !exec.sawUncanceled {
		t.Fatal("rollback must run under a non-cancelled context so cleanup completes")
	}
}

// TestExecuteContextExpiresBeforeFirstApplyRollsBackNothing pins the fix for the
// window where the execution context expires after snapshots are captured but
// before the first apply call. No mutation is ever attempted, so the rollback
// recipe must NOT run: issuing its restore writes here would overwrite concurrent
// state this repair never touched. The outcome is a truthful, stable "no lasting
// change" (rolled_back), and the executor's Apply — forward OR rollback — is never
// invoked at all.
func TestExecuteContextExpiresBeforeFirstApplyRollsBackNothing(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeRoutesDefaultMissing)) // reapply-routes carries a rollback recipe
	pr0, ok := plannedFor(plan, ActionReapplyRoutes)
	if !ok || len(pr0.Rollback) == 0 {
		t.Fatalf("this test needs an action that carries a rollback recipe, got %+v", pr0)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The snapshot capture consumes/expires the execution context: cancellation
	// propagates synchronously to the derived execCtx, so by the time the apply loop
	// runs its very first step is skipped and mutationAttempted stays false.
	exec := &fakeExecutor{onCapture: cancel}
	rep := Execute(ctx, env, plan, exec)

	pr, _ := execFor(rep, ActionReapplyRoutes)
	// Nothing was mutated, so the truthful stable outcome is "no lasting change" —
	// never uncertain (nothing to be uncertain about) and never rollback_failed.
	if pr.Status != RepairRolledBack {
		t.Fatalf("no mutation attempted must report rolled_back (no lasting change), got %q (%s)", pr.Status, pr.Error)
	}
	// The single apply step is recorded as not-OK (the fired deadline), but the
	// executor was never actually invoked for it.
	if len(pr.Applied) != 1 || pr.Applied[0].OK {
		t.Fatalf("the skipped apply step should record as not-OK, got %+v", pr.Applied)
	}
	// The crux: rollback must NOT run when no mutation was attempted.
	if len(pr.RolledBack) != 0 {
		t.Fatalf("rollback must not run when no mutation was attempted, got %+v", pr.RolledBack)
	}
	// Zero apply calls of ANY kind: no forward apply, no restore/rollback apply.
	if len(exec.applied) != 0 {
		t.Fatalf("expected zero apply invocations (forward or rollback), got %+v", exec.applied)
	}
	if exec.sawCancelled || exec.sawUncanceled {
		t.Fatalf("Apply must never have been invoked, cancelled=%v uncanceled=%v", exec.sawCancelled, exec.sawUncanceled)
	}
	// Snapshots (read-only) were still captured before the abort.
	if len(exec.captured) != 1 || exec.captured[0] != "routes" {
		t.Fatalf("snapshot should have been captured before the abort, got %+v", exec.captured)
	}
}

func TestExecutionReportJSONOmitsSnapshotValues(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeRoutesDefaultMissing))
	exec := &fakeExecutor{}
	rep := Execute(context.Background(), env, plan, exec)

	out, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "prior") { // the value fakeExecutor stores in snapshots
		t.Fatalf("execution report leaked snapshot values: %s", s)
	}
	if !strings.Contains(s, `"routes"`) { // the snapshot kind is fine to show
		t.Fatalf("execution report should record snapshot kinds: %s", s)
	}
}

// --- issue 3: MTU repair must never raise the MTU ----------------------------

func TestTooLowMapsToNoAutomaticMTUReset(t *testing.T) {
	// mtu.too_low is diagnostic/manual only: even under a snapshot where lowering
	// would otherwise be safe, a too-low finding must schedule no automatic
	// set-to-1280 repair, because if the measured path is already below 1280,
	// "lowering" to 1280 would raise the MTU and worsen blackholing.
	snap := capableSnap() // link 1500, observed path 1400
	env := planEnv(snap)
	plan := Plan(env, findingsWith(CodeMTUTooLow))
	if pr, ok := plannedFor(plan, ActionLowerMTU); ok {
		t.Fatalf("mtu.too_low must not map to an automatic MTU-lowering repair, got %+v", pr)
	}
	// Sanity: the same snapshot with a suboptimal finding DOES plan the repair.
	if _, ok := plannedFor(Plan(env, findingsWith(CodeMTUSuboptimal)), ActionLowerMTU); !ok {
		t.Fatal("mtu.suboptimal should still map to lower-mtu")
	}
}

func TestLowerMTUNotApplicableWhenFloorUnsafe(t *testing.T) {
	// Path and link are both 1200: setting the tunnel MTU to the 1280 floor would
	// RAISE it past what the path can carry, so the repair must not be applicable
	// and must plan no mutation.
	snap := capableSnap()
	snap.WireGuard.LinkMTU = 1200
	snap.ObservedPathMTU = 1200
	env := planEnv(snap)
	plan := Plan(env, findingsWith(CodeMTUSuboptimal))
	pr, ok := plannedFor(plan, ActionLowerMTU)
	if !ok {
		t.Fatal("expected lower-mtu present in the plan")
	}
	if pr.Applicable {
		t.Fatalf("lower-mtu must not be applicable when 1280 exceeds path/link, got %+v", pr.Preconditions)
	}
	if len(plan.Applicable()) != 0 {
		t.Fatal("no repair should be applicable")
	}
	// It must also be refused at execution time (defence in depth): no mutation.
	exec := &fakeExecutor{}
	rep := Execute(context.Background(), env, plan, exec)
	pe, _ := execFor(rep, ActionLowerMTU)
	if pe.Status != RepairSkipped || !strings.Contains(pe.Error, "precondition") {
		t.Fatalf("an unsafe-floor repair must be skipped at execution time, got %q / %q", pe.Status, pe.Error)
	}
	if len(exec.applied) != 0 || len(exec.captured) != 0 {
		t.Fatal("an unsafe-floor repair must not capture or apply anything")
	}
}

func TestLowerMTUApplicableWhenFloorSafe(t *testing.T) {
	// Measured path 1400, link 1500: 1280 is at or below both, so lowering to the
	// path-safe floor is safe and the repair may be planned and applied.
	snap := capableSnap()
	snap.WireGuard.LinkMTU = 1500
	snap.ObservedPathMTU = 1400
	env := planEnv(snap)
	plan := Plan(env, findingsWith(CodeMTUSuboptimal))
	pr, ok := plannedFor(plan, ActionLowerMTU)
	if !ok || !pr.Applicable {
		t.Fatalf("lower-mtu should be applicable when the floor fits path and link, got %+v", pr)
	}
	if len(pr.Apply) != 1 || pr.Apply[0].Params["mtu"] != "1280" {
		t.Fatalf("the planned mutation must target the 1280 floor, got %+v", pr.Apply)
	}
	exec := &fakeExecutor{}
	rep := Execute(context.Background(), env, plan, exec)
	pe, _ := execFor(rep, ActionLowerMTU)
	if pe.Status != RepairApplied {
		t.Fatalf("a safe-floor repair should apply, got %q (%s)", pe.Status, pe.Error)
	}
}

// --- issue 3b: MTU execute-time TOCTOU guard ---------------------------------

// TestLowerMTUExecuteGuardBlocksWhenLinkDropsBelowFloor proves the execute-time
// guard closes the precondition/mutation window: the plan-time env still shows a
// safe link (1500) and path (1400) so the repair is applicable and its
// precondition passes, but between plan and capture the live link MTU drops to
// 1200. The guard, reading the freshly captured evidence, must abort before any
// mutation — setting 1280 would raise the MTU above the current 1200 link.
func TestLowerMTUExecuteGuardBlocksWhenLinkDropsBelowFloor(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeMTUSuboptimal))
	if pr, ok := plannedFor(plan, ActionLowerMTU); !ok || !pr.Applicable {
		t.Fatalf("precondition must still pass on the safe plan-time env, got %+v", pr)
	}
	exec := &fakeExecutor{mtuLinkCapture: 1200} // live link dropped below the 1280 floor
	rep := Execute(context.Background(), env, plan, exec)
	pe, _ := execFor(rep, ActionLowerMTU)
	if pe.Status != RepairSkipped {
		t.Fatalf("a link MTU that dropped below the floor must abort the repair, got %q (%s)", pe.Status, pe.Error)
	}
	if !strings.Contains(pe.Error, "guard") {
		t.Fatalf("error should cite the execution-time guard, got %q", pe.Error)
	}
	if len(exec.applied) != 0 {
		t.Fatalf("zero mutation expected when the guard aborts, got applied=%+v", exec.applied)
	}
}

// TestLowerMTUExecuteGuardBlocksWhenPathDropsBelowFloor is the path-evidence twin:
// a fresh path MTU that dropped to 1200 must likewise abort with zero mutation.
func TestLowerMTUExecuteGuardBlocksWhenPathDropsBelowFloor(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeMTUSuboptimal))
	exec := &fakeExecutor{mtuPathCapture: 1200} // live path dropped below the 1280 floor
	rep := Execute(context.Background(), env, plan, exec)
	pe, _ := execFor(rep, ActionLowerMTU)
	if pe.Status != RepairSkipped {
		t.Fatalf("a path MTU that dropped below the floor must abort the repair, got %q (%s)", pe.Status, pe.Error)
	}
	if len(exec.applied) != 0 {
		t.Fatalf("zero mutation expected when the guard aborts, got applied=%+v", exec.applied)
	}
}

// TestLowerMTUExecuteGuardFailsClosedWithoutFreshEvidence proves the guard REQUIRES
// fresh, execution-time link and path evidence: if the captured snapshot omits
// either value the repair fails closed with zero mutation, never guessing.
func TestLowerMTUExecuteGuardFailsClosedWithoutFreshEvidence(t *testing.T) {
	cases := map[string]*fakeExecutor{
		"missing path evidence": {mtuOmitPath: true},
		"missing link evidence": {mtuOmitLink: true},
	}
	for name, exec := range cases {
		t.Run(name, func(t *testing.T) {
			env := planEnv(capableSnap())
			plan := Plan(env, findingsWith(CodeMTUSuboptimal))
			rep := Execute(context.Background(), env, plan, exec)
			pe, _ := execFor(rep, ActionLowerMTU)
			if pe.Status != RepairSkipped {
				t.Fatalf("absent fresh evidence must fail closed, got %q (%s)", pe.Status, pe.Error)
			}
			if len(exec.applied) != 0 {
				t.Fatalf("zero mutation expected without fresh evidence, got applied=%+v", exec.applied)
			}
		})
	}
}

// TestLowerMTURollbackRestoresMTUNotBlockedByGuard proves the guard governs only
// the forward mutation: with safe fresh evidence the guard passes and OpSetMTU
// applies, then a failing postcondition forces a rollback whose OpSetMTU restore
// must run to completion. Restoring the prior MTU is never incorrectly blocked.
func TestLowerMTURollbackRestoresMTUNotBlockedByGuard(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeMTUSuboptimal))
	exec := &fakeExecutor{postFail: PostMTUPathSafe}
	rep := Execute(context.Background(), env, plan, exec)
	pe, _ := execFor(rep, ActionLowerMTU)
	if pe.Status != RepairPostconditionFailed {
		t.Fatalf("expected postcondition_failed, got %q (%s)", pe.Status, pe.Error)
	}
	if len(pe.Applied) != 1 || pe.Applied[0].Op != OpSetMTU || !pe.Applied[0].OK {
		t.Fatalf("the forward OpSetMTU must have applied, got %+v", pe.Applied)
	}
	if len(pe.RolledBack) != 1 || pe.RolledBack[0].Op != OpSetMTU || !pe.RolledBack[0].OK {
		t.Fatalf("the rollback OpSetMTU restore must run and complete, got %+v", pe.RolledBack)
	}
}

// --- issue 4: rollback truthfulness ------------------------------------------

func TestExecuteApplyFailureRollbackFailureReportsRollbackFailed(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeRoutesDefaultMissing)) // reapply-routes
	// The apply fails AND the rollback (restore-routes) also fails, so the prior
	// state is not restored. The status must be the distinct rollback_failed.
	exec := &fakeExecutor{failOps: map[RepairOp]bool{OpReapplyRoutes: true, OpRestoreRoutes: true}}
	rep := Execute(context.Background(), env, plan, exec)

	pr, _ := execFor(rep, ActionReapplyRoutes)
	if pr.Status != RepairRollbackFailed {
		t.Fatalf("a failed rollback after a failed apply must report rollback_failed, got %q", pr.Status)
	}
	if len(pr.RolledBack) != 1 || pr.RolledBack[0].OK {
		t.Fatalf("the failed rollback step must be preserved, got %+v", pr.RolledBack)
	}
	if !strings.Contains(pr.Error, "apply failed") || !strings.Contains(pr.Error, "rollback did not complete") {
		t.Fatalf("error must preserve the primary apply failure and the rollback failure, got %q", pr.Error)
	}
}

func TestExecutePostconditionFailureRollbackFailureReportsRollbackFailed(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeRoutesDefaultMissing)) // reapply-routes
	// Apply succeeds, the postcondition fails, and the rollback also fails.
	exec := &fakeExecutor{postFail: PostDefaultRoutePresent, failOps: map[RepairOp]bool{OpRestoreRoutes: true}}
	rep := Execute(context.Background(), env, plan, exec)

	pr, _ := execFor(rep, ActionReapplyRoutes)
	if pr.Status != RepairRollbackFailed {
		t.Fatalf("a failed rollback after a failed postcondition must report rollback_failed, got %q", pr.Status)
	}
	if len(pr.Applied) != 1 || !pr.Applied[0].OK {
		t.Fatalf("the apply step should still be recorded as succeeded, got %+v", pr.Applied)
	}
	if len(pr.RolledBack) != 1 || pr.RolledBack[0].OK {
		t.Fatalf("the failed rollback step must be preserved, got %+v", pr.RolledBack)
	}
	if !strings.Contains(pr.Error, "postcondition") || !strings.Contains(pr.Error, "rollback did not complete") {
		t.Fatalf("error must preserve the primary postcondition failure and the rollback failure, got %q", pr.Error)
	}
}

func TestRollbackFailedNeverExposesSnapshotValues(t *testing.T) {
	env := planEnv(capableSnap())
	plan := Plan(env, findingsWith(CodeRoutesDefaultMissing))
	exec := &fakeExecutor{failOps: map[RepairOp]bool{OpReapplyRoutes: true, OpRestoreRoutes: true}}
	rep := Execute(context.Background(), env, plan, exec)
	out, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "prior") { // the value fakeExecutor stores in snapshots
		t.Fatalf("rollback_failed report leaked snapshot values: %s", out)
	}
	if !strings.Contains(string(out), "rollback_failed") {
		t.Fatalf("expected the rollback_failed status in the report: %s", out)
	}
}

// --- recipe immutability: a plan must never alias the authoritative catalogue -

func planIndexOf(p RepairPlan, id RepairActionID) int {
	for i := range p.Repairs {
		if p.Repairs[i].Action == id {
			return i
		}
	}
	return -1
}

// TestPlanMutationCannotCorruptAuthoritativeRecipe mutates every nested field a
// caller can reach through a returned plan (slices AND the Step.Params maps) and
// proves none of it reaches repairCatalog or repairByID, a later plan still emits
// the pristine recipe, and Execute refuses the tampered plan rather than running
// its forged steps.
func TestPlanMutationCannotCorruptAuthoritativeRecipe(t *testing.T) {
	env := planEnv(capableSnap())
	// lower-mtu is the richest recipe: params-bearing apply, a snapshot, a
	// params-bearing rollback and a postcondition — so mutating "all nested fields"
	// exercises every clone site.
	plan := Plan(env, findingsWith(CodeMTUSuboptimal))
	i := planIndexOf(plan, ActionLowerMTU)
	if i < 0 {
		t.Fatal("expected lower-mtu in the plan")
	}
	pr := &plan.Repairs[i]

	// Mutate every reachable nested field, including inside the Params maps.
	pr.Apply[0].Op = OpFlushDNS
	pr.Apply[0].Desc = "tampered apply"
	pr.Apply[0].Params["mtu"] = "9999"
	pr.Apply[0].Params["injected"] = "evil"
	pr.Rollback[0].Op = OpFlushDNS
	pr.Rollback[0].Desc = "tampered rollback"
	pr.Rollback[0].Params[paramFromSnapshot] = "evil"
	pr.Rollback[0].Params["injected"] = "evil"
	pr.Snapshots[0].Kind = "evil"
	pr.Snapshots[0].Desc = "tampered snapshot"
	pr.Postconditions[0] = PostWireGuardUp
	if len(pr.Addresses) > 0 {
		pr.Addresses[0] = "x.tampered"
	}

	// The authoritative index recipe must be byte-for-byte intact.
	rec := repairByID[ActionLowerMTU]
	if rec.Apply[0].Op != OpSetMTU || rec.Apply[0].Params["mtu"] != "1280" {
		t.Fatalf("repairByID apply corrupted: %+v", rec.Apply)
	}
	if _, ok := rec.Apply[0].Params["injected"]; ok {
		t.Fatal("repairByID apply params gained an injected key")
	}
	if rec.Rollback[0].Op != OpSetMTU || rec.Rollback[0].Params[paramFromSnapshot] != "mtu" {
		t.Fatalf("repairByID rollback corrupted: %+v", rec.Rollback)
	}
	if _, ok := rec.Rollback[0].Params["injected"]; ok {
		t.Fatal("repairByID rollback params gained an injected key")
	}
	if rec.Snapshots[0].Kind != "mtu" {
		t.Fatalf("repairByID snapshot corrupted: %+v", rec.Snapshots)
	}
	if rec.Postconditions[0] != PostMTUPathSafe {
		t.Fatalf("repairByID postcondition corrupted: %+v", rec.Postconditions)
	}

	// The source catalogue slice must likewise be untouched.
	for _, a := range repairCatalog {
		if a.ID != ActionLowerMTU {
			continue
		}
		if a.Apply[0].Op != OpSetMTU || a.Apply[0].Params["mtu"] != "1280" {
			t.Fatalf("repairCatalog apply corrupted: %+v", a.Apply)
		}
		if a.Snapshots[0].Kind != "mtu" || a.Postconditions[0] != PostMTUPathSafe {
			t.Fatalf("repairCatalog entry corrupted: %+v", a)
		}
	}

	// A fresh plan must still emit the pristine recipe.
	fresh := Plan(env, findingsWith(CodeMTUSuboptimal))
	fi := planIndexOf(fresh, ActionLowerMTU)
	if fresh.Repairs[fi].Apply[0].Params["mtu"] != "1280" {
		t.Fatalf("a later plan inherited tampered params: %+v", fresh.Repairs[fi].Apply)
	}

	// Executing the tampered plan must bind to the authoritative recipe and reject
	// the mismatch (or refuse the injected op) — never run the forged steps.
	exec := &fakeExecutor{}
	rep := Execute(context.Background(), env, plan, exec)
	pe, _ := execFor(rep, ActionLowerMTU)
	if pe.Status != RepairSkipped {
		t.Fatalf("a tampered plan must be skipped, got %q (%s)", pe.Status, pe.Error)
	}
	if len(exec.applied) != 0 || len(exec.captured) != 0 {
		t.Fatalf("a tampered plan must not capture or apply anything, applied=%+v captured=%+v", exec.applied, exec.captured)
	}
}

// paramMutatingExecutor is a hostile Executor that mutates the Step.Params map it
// is handed. Because Execute runs from a fresh deep copy of the recipe, this must
// not reach the authoritative catalogue.
type paramMutatingExecutor struct{ *fakeExecutor }

func (m *paramMutatingExecutor) Apply(ctx context.Context, step Step, snaps []SnapshotData) error {
	if step.Params != nil {
		step.Params["mtu"] = "corrupted"
		step.Params["injected"] = "evil"
	}
	return m.fakeExecutor.Apply(ctx, step, snaps)
}

// TestExecutorCannotCorruptAuthoritativeRecipe proves Execute hands the executor
// a fresh, un-aliasable deep copy: a hostile executor mutating its params map
// cannot corrupt repairByID/repairCatalog, and a later repair still runs the
// pristine 1280 recipe.
func TestExecutorCannotCorruptAuthoritativeRecipe(t *testing.T) {
	env := planEnv(capableSnap())
	exec := &paramMutatingExecutor{&fakeExecutor{}}
	rep := Execute(context.Background(), env, Plan(env, findingsWith(CodeMTUSuboptimal)), exec)
	pe, _ := execFor(rep, ActionLowerMTU)
	if pe.Status != RepairApplied {
		t.Fatalf("the safe recipe should apply, got %q (%s)", pe.Status, pe.Error)
	}
	if got := repairByID[ActionLowerMTU].Apply[0].Params["mtu"]; got != "1280" {
		t.Fatalf("executor corrupted repairByID: mtu=%q", got)
	}
	if _, ok := repairByID[ActionLowerMTU].Apply[0].Params["injected"]; ok {
		t.Fatal("executor injected a key into repairByID")
	}
	for _, a := range repairCatalog {
		if a.ID == ActionLowerMTU && a.Apply[0].Params["mtu"] != "1280" {
			t.Fatalf("executor corrupted repairCatalog: mtu=%q", a.Apply[0].Params["mtu"])
		}
	}
	// A subsequent execution must still run the pristine recipe.
	rep2 := Execute(context.Background(), env, Plan(env, findingsWith(CodeMTUSuboptimal)), &fakeExecutor{})
	pe2, _ := execFor(rep2, ActionLowerMTU)
	if pe2.Status != RepairApplied {
		t.Fatalf("a later repair must still apply the pristine recipe, got %q (%s)", pe2.Status, pe2.Error)
	}
}

// TestPlanConcurrentMutationIsRaceFree runs many goroutines that Plan and mutate
// the returned recipes concurrently with others that Plan+Execute, under -race.
// Before recipes were deep-cloned, every plan aliased the catalogue's shared
// Params maps, so concurrent mutation was a data race and corrupted the recipe;
// after cloning each plan owns independent maps, so this is race-free and the
// authoritative recipe stays pristine.
func TestPlanConcurrentMutationIsRaceFree(t *testing.T) {
	env := planEnv(capableSnap())
	fs := findingsWith(CodeMTUSuboptimal, CodeRoutesDefaultMissing, CodeExitEgressBlocked)

	var wg sync.WaitGroup
	const workers = 50
	for w := 0; w < workers; w++ {
		wg.Add(2)
		// Mutators: hammer every nested field of a freshly planned recipe.
		go func() {
			defer wg.Done()
			p := Plan(env, fs)
			for idx := range p.Repairs {
				pr := &p.Repairs[idx]
				for s := range pr.Apply {
					if pr.Apply[s].Params != nil {
						pr.Apply[s].Params["mtu"] = "tampered"
						pr.Apply[s].Params["injected"] = "evil"
					}
				}
				for s := range pr.Rollback {
					if pr.Rollback[s].Params != nil {
						pr.Rollback[s].Params[paramFromSnapshot] = "tampered"
					}
				}
				for s := range pr.Snapshots {
					pr.Snapshots[s].Kind = "tampered"
				}
				for s := range pr.Postconditions {
					pr.Postconditions[s] = PostWireGuardUp
				}
			}
		}()
		// Readers: plan and execute against the authoritative catalogue.
		go func() {
			defer wg.Done()
			Execute(context.Background(), env, Plan(env, fs), &fakeExecutor{})
		}()
	}
	wg.Wait()

	if got := repairByID[ActionLowerMTU].Apply[0].Params["mtu"]; got != "1280" {
		t.Fatalf("concurrent plan mutation corrupted the authoritative recipe: mtu=%q", got)
	}
}

func execFor(r ExecutionReport, id RepairActionID) (RepairExecution, bool) {
	for _, e := range r.Repairs {
		if e.Action == id {
			return e, true
		}
	}
	return RepairExecution{}, false
}

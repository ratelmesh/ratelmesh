package diagnose

import (
	"context"
	"encoding/json"
	"fmt"
)

// The execution seam. This package orchestrates repairs — ordering,
// snapshot-before-apply, rollback-on-failure, allowlist enforcement — but runs
// no privileged command itself. The daemon injects an Executor that implements the
// allowlisted primitives; a fake Executor in _test.go exercises the
// orchestration without any double reaching product code.

// SnapshotData is state the executor captured before a repair, keyed by the
// SnapshotRequest.Kind. Values are opaque to this package and are not emitted in
// the execution report.
type SnapshotData struct {
	Kind   string
	Values map[string]string
}

// Executor performs the privileged half of a repair. Implementations must
// reject any op outside the allowlist and honour ctx. Apply receives the
// snapshots captured for the current repair so a restore op can read prior
// state.
//
// CheckPostcondition is the typed postcondition-check seam: after a repair
// applies, Execute asks the executor whether each of the recipe's documented,
// allowlisted PostconditionID checks holds against freshly observed live state.
// The id is opaque data, never a command string, so a daemon executor maps it to
// a native, read-only observation. It returns ok=false when the check does not
// hold; a non-nil error means the check could not be evaluated. Either outcome
// causes Execute to roll the repair back and report postcondition_failed.
type Executor interface {
	CaptureSnapshot(ctx context.Context, req SnapshotRequest) (SnapshotData, error)
	Apply(ctx context.Context, step Step, snapshots []SnapshotData) error
	CheckPostcondition(ctx context.Context, id PostconditionID, snapshots []SnapshotData) (ok bool, err error)
}

// RepairStatus is the outcome of executing one repair.
type RepairStatus string

const (
	// RepairApplied means every apply step succeeded and every postcondition held.
	RepairApplied RepairStatus = "applied"
	// RepairRolledBack means an apply step failed and the prior state was restored
	// — either rollback ran to completion (every rollback step succeeded) or no
	// mutation was ever attempted (the apply phase aborted before the first apply
	// call, e.g. the execution deadline had already fired), so there was nothing to
	// undo. Either way a UI may safely read this as "no lasting change". It is
	// reported ONLY when restoration is proven; a mutation that was attempted under
	// an action with no rollback recipe is RepairUncertain, never this.
	RepairRolledBack RepairStatus = "rolled_back"
	// RepairPostconditionFailed means every apply step succeeded but a
	// postcondition did not hold (or could not be evaluated) afterward, AND the
	// action's rollback recipe ran to completion, so the prior state WAS restored.
	// It is distinct from RepairRolledBack so a caller can tell "apply failed" from
	// "apply succeeded but left the wrong state"; like RepairRolledBack it means the
	// prior state WAS restored. An action with no rollback recipe can never reach
	// this status — a postcondition failure there is RepairUncertain, because the
	// mutation happened and no recipe can prove the prior state was restored.
	RepairPostconditionFailed RepairStatus = "postcondition_failed"
	// RepairUncertain means a mutation was attempted but the executor cannot prove
	// the prior state was restored: the action declares no rollback recipe, and
	// either an apply step errored/timed out (so it may have partially mutated) or a
	// postcondition did not hold after a clean apply (so a nominally idempotent
	// action left the wrong state). The system may be in a changed or
	// partially-changed state; a caller MUST NOT read this as restored and should
	// surface it for manual intervention. It is deliberately fail-closed: it is the
	// only honest outcome when mutation happened and nothing can undo it. When no
	// mutation was ever attempted the result stays truthful (RepairRolledBack /
	// RepairSnapshotFailed / RepairSkipped), never this.
	RepairUncertain RepairStatus = "uncertain"
	// RepairRollbackFailed means a repair had to be rolled back (because an apply
	// step failed, or a postcondition did not hold) but the rollback itself did
	// not complete — at least one rollback step failed or timed out. The system
	// may be left in a partially-changed state, so this must NOT be read as
	// restored. The primary cause is preserved in Error and every rollback step's
	// own result (including its error) is preserved in RolledBack. It is
	// deliberately distinct from RepairRolledBack/RepairPostconditionFailed, both
	// of which mean the prior state was successfully restored.
	RepairRollbackFailed RepairStatus = "rollback_failed"
	// RepairSnapshotFailed means a pre-apply snapshot failed, so nothing was
	// applied (fail-safe: never mutate state we cannot roll back).
	RepairSnapshotFailed RepairStatus = "snapshot_failed"
	// RepairSkipped means the repair was not applicable or failed validation.
	RepairSkipped RepairStatus = "skipped"
)

// StepResult records one step's execution.
type StepResult struct {
	Op    RepairOp
	OK    bool
	Error string
}

// RepairExecution is the result of executing one planned repair.
type RepairExecution struct {
	Action     RepairActionID
	Status     RepairStatus
	Applied    []StepResult
	RolledBack []StepResult
	Error      string
	// snapshotKinds records which snapshots were captured, for the report; the
	// captured values themselves are deliberately not retained here.
	snapshotKinds []string
}

// ExecutionReport is the result of executing a whole plan.
type ExecutionReport struct {
	Repairs  []RepairExecution
	redactor *Redactor
}

// Execute applies a plan through exec against the trusted, execution-time env.
//
// A plan is untrusted input: it may have been hand-built, tampered with after a
// dry run, or serialised and mutated in transit. Execute therefore trusts none
// of the plan's own claims. For every repair it, in order:
//
//   - rejects a repeated action (a plan may name each action at most once);
//   - re-checks the op allowlist on the plan's steps;
//   - validates the repair against the authoritative catalogue recipe for its
//     action — exact snapshots/apply/rollback shape and parameters — so a plan
//     cannot smuggle malicious parameters or substitute a different recipe under
//     an allowed action id;
//   - re-evaluates the action's live preconditions against env, ignoring the
//     plan's own Applicable bit, which closes the plan-time/execute-time TOCTOU
//     window and defeats a forged Applicable=true;
//   - executes the catalogue's own steps (never the plan's copy), capturing every
//     snapshot before applying anything and, on the first failure of a step it
//     actually invoked, running the full rollback under a detached-but-finite
//     context; if the phase aborts before the first apply call ever runs (e.g. the
//     execution deadline had already fired), no mutation happened, so it rolls back
//     nothing rather than issue restore writes over unchanged state;
//   - after a clean apply, checks every catalogue postcondition against freshly
//     observed live state under the same finite execution context and, on the
//     first failure, runs the same full rollback and reports postcondition_failed.
//
// The whole capture/apply/postcondition phase runs under a finite execution
// context (the caller's context capped by Config.ApplyTimeout), so a caller that
// passes a deadline-less context.Background() cannot wedge a repair forever if an
// Executor honours deadlines. It never runs a privileged command directly, never
// panics on a nil executor, and refuses a nil context outright rather than invent
// a background one that could run privileged work unbounded.
func Execute(ctx context.Context, env *Env, plan RepairPlan, exec Executor) ExecutionReport {
	report := ExecutionReport{redactor: plan.redactor}
	seen := make(map[RepairActionID]bool, len(plan.Repairs))
	for _, pr := range plan.Repairs {
		report.Repairs = append(report.Repairs, executeRepair(ctx, env, pr, exec, seen))
	}
	return report
}

func executeRepair(ctx context.Context, env *Env, pr PlannedRepair, exec Executor, seen map[RepairActionID]bool) RepairExecution {
	ex := RepairExecution{Action: pr.Action}

	// A plan may reference each action at most once. Reject duplicates so a
	// hand-built plan cannot, for example, apply a state-changing repair twice
	// and desynchronise it from its single captured snapshot.
	if seen[pr.Action] {
		ex.Status = RepairSkipped
		ex.Error = fmt.Sprintf("duplicate action %q in plan", pr.Action)
		return ex
	}
	seen[pr.Action] = true

	// Fail safe on missing collaborators rather than panic.
	if exec == nil {
		ex.Status = RepairSkipped
		ex.Error = "no executor provided"
		return ex
	}
	// A nil context is rejected outright: substituting context.Background() would
	// let a caller that forgot to pass a context run privileged capture/apply work
	// with no deadline and no cancellation. Skip the repair without ever invoking
	// the executor.
	if ctx == nil {
		ex.Status = RepairSkipped
		ex.Error = "nil context: refusing to run a repair without a caller context"
		return ex
	}

	// Defence in depth: reject any non-allowlisted op before anything else, so a
	// smuggled op surfaces with an allowlist error.
	if err := validateSteps(pr.Apply, pr.Rollback); err != nil {
		ex.Status = RepairSkipped
		ex.Error = err.Error()
		return ex
	}

	// Bind the repair to the authoritative catalogue recipe for its action and
	// reject any deviation. From here on we execute the catalogue's own steps,
	// not the plan's copy, so even a recipe that happens to match is run from
	// trusted data.
	authoritative, ok := repairByID[pr.Action]
	if !ok {
		ex.Status = RepairSkipped
		ex.Error = fmt.Sprintf("unknown repair action %q", pr.Action)
		return ex
	}
	// Run from a fresh deep copy of the authoritative recipe, never the shared
	// index entry. This keeps the executed steps un-aliasable: neither the
	// untrusted plan nor a misbehaving Executor (which receives Step values whose
	// Params map it could mutate) can reach back into repairByID/repairCatalog and
	// corrupt the recipe a later Execute call will run.
	action := cloneAction(authoritative)
	if err := matchesCatalog(pr, action); err != nil {
		ex.Status = RepairSkipped
		ex.Error = err.Error()
		return ex
	}

	// Re-evaluate the action's preconditions against the trusted execution-time
	// env, ignoring the plan's own Applicable bit. This is the guard against both
	// a plan-time/execute-time TOCTOU change and a forged Applicable=true.
	if env == nil {
		ex.Status = RepairSkipped
		ex.Error = "no execution environment for precondition re-check"
		return ex
	}
	for _, pc := range action.Preconditions {
		if okPre, detail := pc.check(env); !okPre {
			ex.Status = RepairSkipped
			ex.Error = fmt.Sprintf("precondition %q not satisfied at execution time: %s", pc.ID, detail)
			return ex
		}
	}

	// Bound the whole capture/apply/postcondition phase with a finite execution
	// context: the caller's context capped by ApplyTimeout. An earlier caller
	// deadline still wins; a deadline-less Background caller is capped here, so an
	// Executor that honours deadlines can never be wedged forever.
	applyTimeout := env.Config.ApplyTimeout
	if applyTimeout <= 0 {
		applyTimeout = DefaultConfig().ApplyTimeout
	}
	execCtx, cancelExec := context.WithTimeout(ctx, applyTimeout)
	defer cancelExec()

	// Capture every snapshot first (from the catalogue); if any fails, apply
	// nothing.
	snaps := make([]SnapshotData, 0, len(action.Snapshots))
	for _, req := range action.Snapshots {
		data, err := exec.CaptureSnapshot(execCtx, req)
		if err != nil {
			ex.Status = RepairSnapshotFailed
			ex.Error = fmt.Sprintf("snapshot %q failed: %v", req.Kind, err)
			return ex
		}
		snaps = append(snaps, data)
		ex.snapshotKinds = append(ex.snapshotKinds, req.Kind)
	}

	// Execute-time guard: with every snapshot captured, revalidate the mutation
	// against the freshly captured live evidence before applying anything. This is
	// how the MTU repair proves — using the just-captured link and path MTU, not
	// the possibly stale execution-env snapshot the precondition read — that the
	// target does not exceed the current link or path. A guard failure aborts the
	// repair with zero mutation (snapshots are read-only, so there is nothing to
	// undo). The guard runs only here, never in rollback, so a restore step is
	// never blocked by it.
	if action.executeGuard != nil {
		if err := action.executeGuard(env, action, snaps); err != nil {
			ex.Status = RepairSkipped
			ex.Error = fmt.Sprintf("execution-time guard refused the repair: %v", err)
			return ex
		}
	}

	// Apply the catalogue's steps in order, stopping at the first failure.
	// mutationAttempted records whether we actually invoked exec.Apply for at least
	// one step: once we have, we can no longer prove the system is unchanged (a
	// failing Apply may have partially mutated), so the fail-closed outcome differs
	// from a phase that aborted before touching anything.
	var applyErr error
	mutationAttempted := false
	for _, step := range action.Apply {
		if applyErr = execCtx.Err(); applyErr != nil {
			ex.Applied = append(ex.Applied, StepResult{Op: step.Op, OK: false, Error: applyErr.Error()})
			break
		}
		mutationAttempted = true
		err := exec.Apply(execCtx, step, snaps)
		ex.Applied = append(ex.Applied, StepResult{Op: step.Op, OK: err == nil, Error: errString(err)})
		if err != nil {
			applyErr = err
			break
		}
	}

	if applyErr != nil {
		if !mutationAttempted {
			// The execution deadline fired (or the caller's context was already done)
			// before the first apply call, so nothing was ever mutated. Snapshots are
			// read-only, so there is nothing to undo — and running the rollback recipe
			// here would itself issue restore writes that could overwrite concurrent
			// state we never touched. Roll back nothing and truthfully report "no
			// lasting change". This is the only branch reached with mutationAttempted
			// == false, so every branch below runs only after a real apply attempt.
			ex.Status = RepairRolledBack
			ex.Error = applyErr.Error()
			return ex
		}
		// At least one apply step was actually attempted and it failed (or the
		// deadline fired between steps). Run the rollback recipe (a no-op for an
		// idempotent action) and choose a status that never over-claims restoration.
		ex.RolledBack = rollback(ctx, env, action, snaps, exec)
		switch {
		case rollbackFailed(ex.RolledBack):
			// The rollback did not complete, so the prior state was NOT restored.
			// Surface a distinct status a UI cannot misread as "restored", while
			// preserving the primary apply error and every rollback step result.
			ex.Status = RepairRollbackFailed
			ex.Error = fmt.Sprintf("apply failed and rollback did not complete: %v", applyErr)
		case len(action.Rollback) == 0:
			// A mutation was attempted but the action carries no rollback recipe, so
			// nothing can prove the prior state was restored. Never report
			// rolled_back here — the system may be partially changed. Fail closed to
			// an explicit uncertain outcome that a UI surfaces for manual review.
			ex.Status = RepairUncertain
			ex.Error = fmt.Sprintf("apply failed and no rollback recipe exists to restore prior state; manual intervention required: %v", applyErr)
		default:
			// A mutation was attempted and the rollback recipe ran to completion, so
			// the prior state is intact. Truthfully report "no lasting change".
			ex.Status = RepairRolledBack
			ex.Error = applyErr.Error()
		}
		return ex
	}

	// Every step applied. Verify the catalogue's postconditions against freshly
	// observed live state under the same finite execution context. A postcondition
	// that does not hold — or that cannot be evaluated (including because execCtx's
	// deadline fired) — means the repair did not actually achieve its goal, so we
	// roll it back and report postcondition_failed rather than "applied".
	if pcErr := checkPostconditions(execCtx, action.Postconditions, snaps, exec); pcErr != nil {
		// Apply fully succeeded, so a mutation definitely happened. Run the rollback
		// recipe and choose a status that never over-claims restoration.
		ex.RolledBack = rollback(ctx, env, action, snaps, exec)
		switch {
		case rollbackFailed(ex.RolledBack):
			// Apply succeeded but the postcondition failed AND the rollback did not
			// complete, so the (bad) applied state may persist. Report the distinct
			// rollback-failed status, preserving the primary postcondition error and
			// every rollback step result.
			ex.Status = RepairRollbackFailed
			ex.Error = fmt.Sprintf("postcondition failed and rollback did not complete: %v", pcErr)
		case len(action.Rollback) == 0:
			// A nominally idempotent action mutated (apply succeeded) but its
			// postcondition did not hold, and it declares no rollback recipe. There is
			// nothing that can prove the prior state was restored, so this must NEVER
			// report postcondition_failed (which asserts restoration). Fail closed to
			// an explicit uncertain outcome: the applied-but-wrong state may persist
			// and needs manual intervention.
			ex.Status = RepairUncertain
			ex.Error = fmt.Sprintf("postcondition failed and no rollback recipe exists to restore prior state; manual intervention required: %v", pcErr)
		default:
			// Apply succeeded, the postcondition failed, and the rollback recipe ran
			// to completion, so the prior state WAS restored.
			ex.Status = RepairPostconditionFailed
			ex.Error = pcErr.Error()
		}
		return ex
	}

	ex.Status = RepairApplied
	return ex
}

// checkPostconditions runs each of the recipe's typed postcondition checks
// against freshly observed state. It returns the first failure (either a check
// that does not hold or one that could not be evaluated) or nil if all hold.
func checkPostconditions(ctx context.Context, ids []PostconditionID, snaps []SnapshotData, exec Executor) error {
	for _, id := range ids {
		ok, err := exec.CheckPostcondition(ctx, id, snaps)
		if err != nil {
			return fmt.Errorf("postcondition %q could not be verified: %v", id, err)
		}
		if !ok {
			return fmt.Errorf("postcondition %q did not hold after apply", id)
		}
	}
	return nil
}

// rollback runs the action's rollback steps and returns their results. It
// detaches from the caller's cancellation so cleanup runs even if the caller
// gave up mid-apply (or the execution context's deadline already fired), but
// caps itself with a finite deadline so an Executor that ignores cancellation yet
// honours deadlines can never wedge the rollback forever. An idempotent action
// has no rollback steps, so this is a no-op that returns nil.
func rollback(ctx context.Context, env *Env, action RepairAction, snaps []SnapshotData, exec Executor) []StepResult {
	if len(action.Rollback) == 0 {
		return nil
	}
	rbTimeout := env.Config.RollbackTimeout
	if rbTimeout <= 0 {
		rbTimeout = DefaultConfig().RollbackTimeout
	}
	rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rbTimeout)
	defer cancel()
	var out []StepResult
	for _, step := range action.Rollback {
		err := exec.Apply(rbCtx, step, snaps)
		out = append(out, StepResult{Op: step.Op, OK: err == nil, Error: errString(err)})
	}
	return out
}

// rollbackFailed reports whether any rollback step did not succeed. An empty
// rollback (an idempotent action, or a repair that never needed one) is not a
// failure — there was nothing to restore.
func rollbackFailed(steps []StepResult) bool {
	for _, s := range steps {
		if !s.OK {
			return true
		}
	}
	return false
}

// validateSteps rejects any step whose op is outside the allowlist. It is a
// defence-in-depth check on top of the catalogue invariants, in case a plan was
// assembled by hand.
func validateSteps(groups ...[]Step) error {
	for _, g := range groups {
		for _, s := range g {
			if !allowedOps[s.Op] {
				return fmt.Errorf("diagnose: refusing non-allowlisted op %q", s.Op)
			}
		}
	}
	return nil
}

// matchesCatalog verifies that a planned repair's snapshots, apply steps and
// rollback steps are byte-for-byte the authoritative recipe for its action. It
// deliberately ignores the plan's Title, Addresses, Applicable and Precondition
// fields: those are client-supplied display/decision hints that Execute never
// trusts. A mismatch means the plan was hand-built or tampered with and is
// rejected.
func matchesCatalog(pr PlannedRepair, action RepairAction) error {
	if !snapshotsEqual(pr.Snapshots, action.Snapshots) {
		return fmt.Errorf("diagnose: repair %q snapshots do not match the authoritative recipe", pr.Action)
	}
	if !stepsEqual(pr.Apply, action.Apply) {
		return fmt.Errorf("diagnose: repair %q apply steps do not match the authoritative recipe", pr.Action)
	}
	if !stepsEqual(pr.Rollback, action.Rollback) {
		return fmt.Errorf("diagnose: repair %q rollback steps do not match the authoritative recipe", pr.Action)
	}
	if !postconditionsEqual(pr.Postconditions, action.Postconditions) {
		return fmt.Errorf("diagnose: repair %q postconditions do not match the authoritative recipe", pr.Action)
	}
	return nil
}

// postconditionsEqual reports whether two postcondition-id lists are identical
// in order. A plan that omits, reorders or substitutes postconditions is a
// tampered plan and must be rejected, so the checks Execute actually runs are
// exactly the catalogue's.
func postconditionsEqual(a, b []PostconditionID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// snapshotsEqual reports whether two snapshot-request lists request the same
// kinds in the same order. The Desc is cosmetic and not compared.
func snapshotsEqual(a, b []SnapshotRequest) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Kind != b[i].Kind {
			return false
		}
	}
	return true
}

// stepsEqual reports whether two step lists carry the same ops with the same
// parameters, in the same order. Op and Params are the only fields the executor
// acts on, so they are what must match exactly; the Desc is cosmetic.
func stepsEqual(a, b []Step) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Op != b[i].Op || !paramsEqual(a[i].Params, b[i].Params) {
			return false
		}
	}
	return true
}

// paramsEqual compares two parameter maps, treating a nil map and an empty map
// as equal (JSON round-tripping a step with no params yields nil).
func paramsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Execution-report wire structs.
type execReportWire struct {
	Schema  string           `json:"schema"`
	Repairs []execRepairWire `json:"repairs"`
}

type execRepairWire struct {
	Action     RepairActionID   `json:"action"`
	Status     RepairStatus     `json:"status"`
	Applied    []stepResultWire `json:"applied,omitempty"`
	RolledBack []stepResultWire `json:"rolled_back,omitempty"`
	Snapshots  []string         `json:"snapshots,omitempty"`
	Error      string           `json:"error,omitempty"`
}

type stepResultWire struct {
	Op    RepairOp `json:"op"`
	OK    bool     `json:"ok"`
	Error string   `json:"error,omitempty"`
}

const execReportSchema = "ratelmesh.diagnose.repair-execution/v1"

// MarshalJSON renders the execution report through the redactor. Captured
// snapshot values are never included — only the kinds that were captured.
func (r ExecutionReport) MarshalJSON() ([]byte, error) {
	w := execReportWire{Schema: execReportSchema}
	for _, rep := range r.Repairs {
		rw := execRepairWire{
			Action:    rep.Action,
			Status:    rep.Status,
			Snapshots: rep.snapshotKinds,
			Error:     shareableRepairError(rep.Status, rep.Error),
		}
		for _, s := range rep.Applied {
			rw.Applied = append(rw.Applied, shareableStepResult(s))
		}
		for _, s := range rep.RolledBack {
			rw.RolledBack = append(rw.RolledBack, shareableStepResult(s))
		}
		w.Repairs = append(w.Repairs, rw)
	}
	raw, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	red := r.redactor
	if red == nil {
		red = NewRedactor(nil)
	}
	return red.RedactJSON(raw)
}

// shareableRepairError intentionally does not serialize executor error text.
// Executor implementations commonly include device names, paths, addresses or
// command output in errors. The stable status/action/step fields carry the
// actionable contract without exporting that private text.
func shareableRepairError(status RepairStatus, raw string) string {
	if raw == "" {
		return ""
	}
	return "repair_" + string(status)
}

func shareableStepResult(result StepResult) stepResultWire {
	out := stepResultWire{Op: result.Op, OK: result.OK}
	if result.Error != "" {
		out.Error = "operation_failed"
	}
	return out
}

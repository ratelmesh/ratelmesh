package diagnose

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// This file defines the declarative, allowlisted repair model. A repair is data,
// never code: an allowlisted operation to apply, the state to snapshot first,
// the preconditions to verify, and the explicit rollback steps to undo it. This
// package plans and orchestrates repairs but executes nothing privileged; Wade
// injects the privileged Executor later (see repair_exec.go).

// RepairOp is an allowlisted repair operation. The executor understands a fixed,
// closed set of ops, so a plan can never smuggle an arbitrary command through.
type RepairOp string

const (
	// Idempotent, stateless recovery ops (no rollback needed).
	OpFlushDNS        RepairOp = "dns.flush_cache"
	OpReconnectCoord  RepairOp = "coordinator.reconnect"
	OpReselectRelay   RepairOp = "relay.reselect"
	OpRearmKillSwitch RepairOp = "killswitch.rearm"

	// State-changing ops (paired with a snapshot + restore op).
	OpSetMTU           RepairOp = "mtu.set"
	OpReapplyRoutes    RepairOp = "routes.reapply"
	OpRestartWireGuard RepairOp = "wireguard.restart"
	OpClearExit        RepairOp = "exit.clear"

	// Restore ops, used only in rollback steps; they consume a captured
	// snapshot to return to the prior state.
	OpRestoreRoutes   RepairOp = "routes.restore"
	OpRestoreWGConfig RepairOp = "wireguard.restore_config"
	OpSetExit         RepairOp = "exit.set"
)

// allowedOps is the closed set the planner emits and the executor accepts.
var allowedOps = map[RepairOp]bool{
	OpFlushDNS:         true,
	OpReconnectCoord:   true,
	OpReselectRelay:    true,
	OpRearmKillSwitch:  true,
	OpSetMTU:           true,
	OpReapplyRoutes:    true,
	OpRestartWireGuard: true,
	OpClearExit:        true,
	OpRestoreRoutes:    true,
	OpRestoreWGConfig:  true,
	OpSetExit:          true,
}

// AllowedOp reports whether op is in the allowlist.
func AllowedOp(op RepairOp) bool { return allowedOps[op] }

// paramFromSnapshot is the Step param whose value names the SnapshotRequest.Kind
// a (restore) step reads its prior state from.
const paramFromSnapshot = "from_snapshot"

// Step is one declarative operation in a repair. Params are redaction-safe
// key/values (never secrets); the executor interprets them per Op.
type Step struct {
	Op     RepairOp          `json:"op"`
	Params map[string]string `json:"params,omitempty"`
	Desc   string            `json:"description,omitempty"`
}

// SnapshotRequest asks the executor to capture a piece of state before a repair
// runs, so a rollback can restore it.
type SnapshotRequest struct {
	Kind string `json:"kind"`
	Desc string `json:"description,omitempty"`
}

// Precondition is a read-only check that decides whether a repair is safe to
// apply. Its evaluator is unexported and never serialised; the evaluated
// PreconditionResult is what appears in the plan.
type Precondition struct {
	ID    string
	Desc  string
	check func(*Env) (bool, string)
}

// PreconditionResult is the outcome of evaluating a Precondition.
type PreconditionResult struct {
	ID     string
	Desc   string
	OK     bool
	Detail string
}

// PostconditionID names a typed, read-only success check a repair must satisfy
// after it applies. It is deliberately an opaque, allowlisted identifier and
// never a command string: an executor maps each ID to a native read-only
// observation of live state (for example "is the tunnel default route present")
// and reports only whether it holds. A repair whose postcondition does not hold
// after apply is rolled back, so a repair that "succeeds" but leaves the system
// in the wrong state is treated as a failure rather than reported as fixed.
type PostconditionID string

const (
	// PostDNSResolves verifies the resolver answers after a cache flush.
	PostDNSResolves PostconditionID = "dns.resolves"
	// PostCoordinatorConnected verifies the control-plane session is live again.
	PostCoordinatorConnected PostconditionID = "coordinator.connected"
	// PostRelayReachable verifies a relay is reachable after reselection.
	PostRelayReachable PostconditionID = "relay.reachable"
	// PostKillSwitchArmed verifies fail-closed filtering (incl. IPv6) is armed.
	PostKillSwitchArmed PostconditionID = "killswitch.armed"
	// PostMTUPathSafe verifies the tunnel MTU the repair configured is safe
	// relative to the observed path — that is, the configured MTU is less than or
	// equal to the measured path MTU (and so cannot itself blackhole traffic). It
	// deliberately does NOT mean "equal to a constant": an executor maps it to a
	// live observation that the configured MTU fits the path, so a repair that set
	// a value the path cannot carry is treated as failed, not fixed.
	PostMTUPathSafe PostconditionID = "mtu.path_safe"
	// PostDefaultRoutePresent verifies a default route is present after reapply.
	PostDefaultRoutePresent PostconditionID = "routes.default_present"
	// PostWireGuardUp verifies the WireGuard interface is up after a rebuild.
	PostWireGuardUp PostconditionID = "wireguard.interface_up"
	// PostExitRoutePresent verifies the exit's route is installed after rebuild.
	PostExitRoutePresent PostconditionID = "exit.route_present"
)

// allowedPostconditions is the closed set of postcondition identifiers the
// planner emits and the executor is asked to check. Like ops and actions, it is
// an allowlist so a tampered plan cannot smuggle an unknown check.
var allowedPostconditions = map[PostconditionID]bool{
	PostDNSResolves:          true,
	PostCoordinatorConnected: true,
	PostRelayReachable:       true,
	PostKillSwitchArmed:      true,
	PostMTUPathSafe:          true,
	PostDefaultRoutePresent:  true,
	PostWireGuardUp:          true,
	PostExitRoutePresent:     true,
}

// AllowedPostcondition reports whether id is in the allowlist.
func AllowedPostcondition(id PostconditionID) bool { return allowedPostconditions[id] }

// RepairActionID is an allowlisted repair identifier.
type RepairActionID string

const (
	ActionFlushDNS             RepairActionID = "flush-dns"
	ActionReconnectCoordinator RepairActionID = "reconnect-coordinator"
	ActionReselectRelay        RepairActionID = "reselect-relay"
	ActionLowerMTU             RepairActionID = "lower-mtu"
	ActionReapplyRoutes        RepairActionID = "reapply-routes"
	ActionRestartWireGuard     RepairActionID = "restart-wireguard"
	ActionRearmKillSwitch      RepairActionID = "rearm-killswitch"
	ActionRebuildExit          RepairActionID = "rebuild-exit"
)

// allowedActions is the closed set of repair identifiers.
var allowedActions = map[RepairActionID]bool{
	ActionFlushDNS:             true,
	ActionReconnectCoordinator: true,
	ActionReselectRelay:        true,
	ActionLowerMTU:             true,
	ActionReapplyRoutes:        true,
	ActionRestartWireGuard:     true,
	ActionRearmKillSwitch:      true,
	ActionRebuildExit:          true,
}

// RepairAction is a catalogue entry: the declarative recipe for fixing one or
// more findings.
type RepairAction struct {
	ID    RepairActionID
	Title string
	// Fixes lists the finding codes this action addresses.
	Fixes []Code
	// Idempotent marks an action that converges on repeated application and
	// needs no snapshot or rollback (for example flushing a DNS cache).
	Idempotent bool
	// Preconditions must all pass for the action to be Applicable.
	Preconditions []Precondition
	// Snapshots are captured (in order) before Apply runs.
	Snapshots []SnapshotRequest
	// Apply is the ordered list of steps that perform the repair.
	Apply []Step
	// Rollback is the ordered list of steps that undo it, using the snapshots.
	Rollback []Step
	// Postconditions are the typed, read-only checks that must all hold after
	// Apply for the repair to count as successful. If any fails, the repair is
	// rolled back (an idempotent action has nothing to roll back, so it only
	// reports the failure). They are documented, allowlisted IDs, never commands.
	Postconditions []PostconditionID

	// executeGuard, when non-nil, runs at execution time AFTER every snapshot has
	// been captured but BEFORE any Apply step. Unlike a Precondition (which reads
	// only the execution-time env, whose snapshot was taken before capture), the
	// guard also sees the freshly captured SnapshotData, so it can revalidate a
	// mutation against live, just-observed evidence and close the window between
	// the precondition check and the mutation. It is unexported code — never
	// serialised, never plan-supplied, and immutable like a Precondition's check —
	// so it neither travels in a plan nor weakens catalogue immutability. A guard
	// that returns an error aborts the repair before any mutation (zero Apply). It
	// never runs during rollback, so a restore step is never blocked by it.
	executeGuard func(env *Env, action RepairAction, snaps []SnapshotData) error
}

// repairFloorMTU is the path-safe tunnel MTU the MTU-lowering repair sets. It is
// the same 1280-byte floor DefaultConfig uses. The MTU-lowering repair may only
// apply when this value is at or below both the observed path and the current
// link MTU, so lowering can never itself *raise* the MTU and worsen blackholing.
const repairFloorMTU = 1280

// mtuSnapshotKind is the SnapshotRequest.Kind the MTU-lowering repair captures
// before it mutates the MTU, so a rollback can restore the prior value.
const mtuSnapshotKind = "mtu"

const (
	// snapKeyLinkMTU is the SnapshotData.Values key under which an executor records
	// the live interface (link) MTU it observed while capturing an mtuSnapshotKind
	// snapshot. It is the freshest, execution-time link MTU — captured after the
	// preMTULowerSafe precondition ran — and mtuLowerExecuteGuard revalidates the
	// requested floor against it to close the precondition/mutation TOCTOU window.
	snapKeyLinkMTU = "link_mtu"
	// snapKeyPathMTU is the SnapshotData.Values key under which an executor records
	// a freshly measured path MTU at capture time. It is the required execution-time
	// path evidence; if it is absent or unparseable the MTU guard fails closed and
	// no mutation runs.
	snapKeyPathMTU = "path_mtu"
)

// preconditions used across the catalogue.
var (
	preDNSCapable      = Precondition{"dns_capable", "a resolver or DNS server is available", pcDNSCapable}
	preWireGuard       = Precondition{"wireguard_configured", "a WireGuard interface exists", pcWireGuardConfigured}
	preExitSelected    = Precondition{"exit_selected", "an exit is currently selected", pcExitSelected}
	preRelayConfigured = Precondition{"relay_configured", "at least one relay is configured", pcRelayConfigured}
	preCoordConfigured = Precondition{"coordinator_configured", "a coordinator endpoint is configured", pcCoordConfigured}
	preMTULowerSafe    = Precondition{"mtu_lower_safe", "lowering to the path-safe floor cannot raise the MTU", pcMTULowerSafe}
)

func pcDNSCapable(env *Env) (bool, string) {
	if env.Deps.Resolver != nil || len(env.Snapshot.DNS.Servers) > 0 {
		return true, ""
	}
	return false, "no resolver or configured DNS server"
}

func pcWireGuardConfigured(env *Env) (bool, string) {
	if env.Snapshot.WireGuard.Interface != "" {
		return true, ""
	}
	return false, "no WireGuard interface is configured"
}

func pcExitSelected(env *Env) (bool, string) {
	if env.Snapshot.Exit != nil {
		return true, ""
	}
	return false, "no exit is selected"
}

func pcRelayConfigured(env *Env) (bool, string) {
	if len(env.Snapshot.Relays) > 0 {
		return true, ""
	}
	return false, "no relay is configured"
}

func pcCoordConfigured(env *Env) (bool, string) {
	if env.Snapshot.Coordinator.Host != "" {
		return true, ""
	}
	return false, "no coordinator endpoint is configured"
}

// pcMTULowerSafe gates the MTU-lowering repair on typed evidence — the observed
// path MTU and the current link MTU from the snapshot — rather than trusting the
// plan's own claims. Lowering the tunnel MTU to repairFloorMTU is only safe when
// that floor is at or below BOTH the observed path MTU and the current link MTU;
// otherwise "lowering" would actually raise the configured MTU past what the path
// can carry and worsen blackholing. If either value is unknown it fails closed:
// without evidence, the repair is not applicable.
func pcMTULowerSafe(env *Env) (bool, string) {
	path := env.Snapshot.ObservedPathMTU
	link := env.Snapshot.WireGuard.LinkMTU
	if path <= 0 || link <= 0 {
		return false, "path or link MTU is unknown; refusing to change MTU without evidence the floor is safe"
	}
	if repairFloorMTU > path || repairFloorMTU > link {
		return false, fmt.Sprintf("the %d-byte floor exceeds the observed path (%d) or link (%d) MTU; lowering would worsen blackholing", repairFloorMTU, path, link)
	}
	return true, ""
}

// mtuLowerExecuteGuard is the MTU-lowering repair's execute-time revalidation. It
// runs after the "mtu" snapshot is captured and before the OpSetMTU mutation,
// closing the window between preMTULowerSafe (which reads the execution-env
// snapshot taken *before* capture and can therefore be stale) and the moment the
// MTU is actually changed. It revalidates that the requested target MTU does not
// exceed EITHER the freshly captured live link MTU OR the fresh path evidence
// carried in the snapshot, so the repair can never transiently raise the MTU
// above what the current link or path can carry. Fresh path evidence is REQUIRED:
// if the snapshot omits the link or path value, or it cannot be parsed, the guard
// fails closed and no mutation runs. Because it reads the requested value from the
// action's own (catalogue-bound) OpSetMTU step, it stays correct if the floor ever
// changes.
func mtuLowerExecuteGuard(env *Env, action RepairAction, snaps []SnapshotData) error {
	requested, ok := requestedSetMTU(action)
	if !ok {
		return fmt.Errorf("mtu repair carries no parseable target MTU; refusing to mutate")
	}
	link, ok := capturedMTU(snaps, mtuSnapshotKind, snapKeyLinkMTU)
	if !ok {
		return fmt.Errorf("mtu snapshot omits fresh live link MTU (%s); refusing to change MTU without execution-time link evidence", snapKeyLinkMTU)
	}
	path, ok := capturedMTU(snaps, mtuSnapshotKind, snapKeyPathMTU)
	if !ok {
		return fmt.Errorf("mtu snapshot omits fresh path MTU evidence (%s); refusing to change MTU without execution-time path evidence", snapKeyPathMTU)
	}
	if requested > link {
		return fmt.Errorf("target MTU %d exceeds the freshly captured link MTU %d; setting it would raise the MTU above the current link and worsen blackholing", requested, link)
	}
	if requested > path {
		return fmt.Errorf("target MTU %d exceeds the fresh path MTU %d; setting it would raise the MTU above the path and worsen blackholing", requested, path)
	}
	return nil
}

// requestedSetMTU extracts the integer MTU an action's OpSetMTU apply step
// requests (its "mtu" param). It reports ok=false if the action sets no MTU or the
// value is unparseable, so the guard can fail closed rather than guess.
func requestedSetMTU(action RepairAction) (int, bool) {
	for _, s := range action.Apply {
		if s.Op != OpSetMTU {
			continue
		}
		v, ok := s.Params["mtu"]
		if !ok {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// capturedMTU reads a positive integer MTU from the first captured snapshot of
// the given kind under key. It reports ok=false when no such snapshot exists, the
// key is absent, or the value is not a positive integer — every "no fresh
// evidence" case, so the guard fails closed.
func capturedMTU(snaps []SnapshotData, kind, key string) (int, bool) {
	for _, s := range snaps {
		if s.Kind != kind {
			continue
		}
		v, ok := s.Values[key]
		if !ok {
			return 0, false
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// repairCatalog is the authoritative, ordered set of repair actions. Its order
// is the order repairs appear in a plan. Every entry must satisfy the
// invariants enforced by validateCatalog.
var repairCatalog = []RepairAction{
	{
		ID:             ActionFlushDNS,
		Title:          "Flush the DNS resolver cache",
		Fixes:          []Code{CodeDNSPoisonSuspected, CodeDNSTimeout, CodeDNSNoAnswer},
		Idempotent:     true,
		Preconditions:  []Precondition{preDNSCapable},
		Apply:          []Step{{Op: OpFlushDNS, Desc: "flush cached DNS answers"}},
		Postconditions: []PostconditionID{PostDNSResolves},
	},
	{
		ID:             ActionReconnectCoordinator,
		Title:          "Reconnect the control-plane session",
		Fixes:          []Code{CodeCoordinatorUnreachable, CodeCoordinatorUnhealthy, CodeCoordinatorTLSError},
		Idempotent:     true,
		Preconditions:  []Precondition{preCoordConfigured},
		Apply:          []Step{{Op: OpReconnectCoord, Desc: "re-establish the coordinator connection"}},
		Postconditions: []PostconditionID{PostCoordinatorConnected},
	},
	{
		ID:             ActionReselectRelay,
		Title:          "Re-select a reachable relay",
		Fixes:          []Code{CodeRelayNoneReachable, CodeRelayUnreachable},
		Idempotent:     true,
		Preconditions:  []Precondition{preRelayConfigured},
		Apply:          []Step{{Op: OpReselectRelay, Desc: "choose a reachable relay from the configured set"}},
		Postconditions: []PostconditionID{PostRelayReachable},
	},
	{
		ID:             ActionRearmKillSwitch,
		Title:          "Re-arm the kill switch to close an IPv6 leak",
		Fixes:          []Code{CodeIPv6LeakRisk},
		Idempotent:     true,
		Preconditions:  []Precondition{preExitSelected},
		Apply:          []Step{{Op: OpRearmKillSwitch, Desc: "re-apply fail-closed filtering including IPv6"}},
		Postconditions: []PostconditionID{PostKillSwitchArmed},
	},
	{
		ID:    ActionLowerMTU,
		Title: "Lower the tunnel MTU to the path-safe floor",
		// mtu.too_low is deliberately NOT fixed here: setting the MTU to the
		// 1280 floor when the measured path is already below it would RAISE the
		// MTU and worsen blackholing. A too-low path is diagnostic/manual only.
		// Only mtu.suboptimal (a path below the link, so packets fragment) is
		// safely addressed by lowering to the floor, and only when the floor is
		// provably at or below both the observed path and the link (see
		// preMTULowerSafe).
		Fixes:          []Code{CodeMTUSuboptimal},
		Preconditions:  []Precondition{preWireGuard, preMTULowerSafe},
		Snapshots:      []SnapshotRequest{{Kind: mtuSnapshotKind, Desc: "current interface MTU"}},
		Apply:          []Step{{Op: OpSetMTU, Params: map[string]string{"mtu": strconv.Itoa(repairFloorMTU)}, Desc: "set the tunnel MTU to the path-safe floor"}},
		Rollback:       []Step{{Op: OpSetMTU, Params: map[string]string{paramFromSnapshot: mtuSnapshotKind}, Desc: "restore the prior MTU"}},
		Postconditions: []PostconditionID{PostMTUPathSafe},
		// Execute-time guard: after capturing the live MTU, revalidate the target
		// against the freshly captured link and path evidence before mutating, so a
		// link/path that dropped below the floor between the precondition check and
		// capture aborts the repair with zero mutation.
		executeGuard: mtuLowerExecuteGuard,
	},
	{
		ID:             ActionReapplyRoutes,
		Title:          "Re-apply the tunnel routing plan",
		Fixes:          []Code{CodeRoutesDefaultMissing, CodeRoutesExitDefaultAbsent, CodeRoutesPhysicalFallback},
		Preconditions:  []Precondition{preWireGuard},
		Snapshots:      []SnapshotRequest{{Kind: "routes", Desc: "current routing table"}},
		Apply:          []Step{{Op: OpReapplyRoutes, Desc: "recompute and install tunnel routes from the netmap"}},
		Rollback:       []Step{{Op: OpRestoreRoutes, Params: map[string]string{paramFromSnapshot: "routes"}, Desc: "restore the captured routing table"}},
		Postconditions: []PostconditionID{PostDefaultRoutePresent},
	},
	{
		ID:             ActionRestartWireGuard,
		Title:          "Rebuild the WireGuard interface",
		Fixes:          []Code{CodeWireGuardInterfaceDown, CodeWireGuardHandshakeStale, CodeExitHandshakeStale},
		Preconditions:  []Precondition{preWireGuard},
		Snapshots:      []SnapshotRequest{{Kind: "wireguard-config", Desc: "current WireGuard configuration"}},
		Apply:          []Step{{Op: OpRestartWireGuard, Desc: "tear down and rebuild the WireGuard interface"}},
		Rollback:       []Step{{Op: OpRestoreWGConfig, Params: map[string]string{paramFromSnapshot: "wireguard-config"}, Desc: "restore the captured WireGuard configuration"}},
		Postconditions: []PostconditionID{PostWireGuardUp},
	},
	{
		ID:            ActionRebuildExit,
		Title:         "Rebuild the selected exit path",
		Fixes:         []Code{CodeExitEgressBlocked, CodeExitRouteMissing},
		Preconditions: []Precondition{preExitSelected},
		Snapshots:     []SnapshotRequest{{Kind: "exit-selection", Desc: "currently selected exit"}},
		Apply: []Step{
			{Op: OpClearExit, Desc: "withdraw the current exit routes"},
			{Op: OpSetExit, Params: map[string]string{paramFromSnapshot: "exit-selection"}, Desc: "re-select the same exit to rebuild its path"},
		},
		Rollback:       []Step{{Op: OpSetExit, Params: map[string]string{paramFromSnapshot: "exit-selection"}, Desc: "re-select the captured exit"}},
		Postconditions: []PostconditionID{PostExitRoutePresent},
	},
}

// cloneParams returns an independent copy of a Step's params map. A nil map
// stays nil (JSON round-tripping a step with no params yields nil, and
// paramsEqual treats nil and empty as equal), so cloning never turns a nil map
// into a non-nil empty one.
func cloneParams(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// cloneSteps deep-copies a step slice, giving every Step its own Params map so a
// mutation of a copy can never reach the original slice's backing array or any
// step's map.
func cloneSteps(in []Step) []Step {
	if in == nil {
		return nil
	}
	out := make([]Step, len(in))
	for i, s := range in {
		out[i] = Step{Op: s.Op, Params: cloneParams(s.Params), Desc: s.Desc}
	}
	return out
}

// cloneSnapshots copies a snapshot-request slice. SnapshotRequest holds only
// value fields, so a fresh backing array is a full deep copy.
func cloneSnapshots(in []SnapshotRequest) []SnapshotRequest {
	if in == nil {
		return nil
	}
	out := make([]SnapshotRequest, len(in))
	copy(out, in)
	return out
}

// cloneCodes copies a code slice into a fresh backing array.
func cloneCodes(in []Code) []Code {
	if in == nil {
		return nil
	}
	out := make([]Code, len(in))
	copy(out, in)
	return out
}

// clonePreconditions copies a precondition slice into a fresh backing array.
// Precondition carries a func value (immutable code), so sharing the func across
// copies is safe; only the slice header must be independent.
func clonePreconditions(in []Precondition) []Precondition {
	if in == nil {
		return nil
	}
	out := make([]Precondition, len(in))
	copy(out, in)
	return out
}

// clonePostconditions copies a postcondition-id slice into a fresh backing array.
func clonePostconditions(in []PostconditionID) []PostconditionID {
	if in == nil {
		return nil
	}
	out := make([]PostconditionID, len(in))
	copy(out, in)
	return out
}

// cloneAction returns a deep copy of a whole recipe: every slice gets a fresh
// backing array and every nested Step.Params map is independent. Nothing a
// caller can reach through the copy aliases the authoritative catalogue, so
// mutating a returned/planned recipe can never corrupt repairCatalog, repairByID,
// or the recipe another Execute call runs.
func cloneAction(a RepairAction) RepairAction {
	return RepairAction{
		ID:             a.ID,
		Title:          a.Title,
		Fixes:          cloneCodes(a.Fixes),
		Idempotent:     a.Idempotent,
		Preconditions:  clonePreconditions(a.Preconditions),
		Snapshots:      cloneSnapshots(a.Snapshots),
		Apply:          cloneSteps(a.Apply),
		Rollback:       cloneSteps(a.Rollback),
		Postconditions: clonePostconditions(a.Postconditions),
		// executeGuard is immutable code (like a Precondition's check); sharing the
		// func value across copies is safe and keeps the guard bound to the recipe.
		executeGuard: a.executeGuard,
	}
}

// repairByID indexes the authoritative catalogue by action id so Execute can
// bind an untrusted planned repair to its trusted recipe in O(1). It is built
// once from repairCatalog, deep-cloning each recipe so the index shares no slice
// or map with repairCatalog (or with any plan derived from it).
var repairByID = func() map[RepairActionID]RepairAction {
	m := make(map[RepairActionID]RepairAction, len(repairCatalog))
	for _, a := range repairCatalog {
		m[a.ID] = cloneAction(a)
	}
	return m
}()

// validateCatalog enforces the invariants that make repairs safe: every action
// and op is allowlisted, every action fixes at least one known code, a
// non-idempotent action carries both a snapshot and a rollback, an idempotent
// action carries neither, and every snapshot-consuming step names a snapshot the
// action actually captures. It returns the first violation found.
func validateCatalog(catalog []RepairAction) error {
	seen := make(map[RepairActionID]bool)
	for _, a := range catalog {
		if !allowedActions[a.ID] {
			return fmt.Errorf("diagnose: repair action %q is not allowlisted", a.ID)
		}
		if seen[a.ID] {
			return fmt.Errorf("diagnose: duplicate repair action %q", a.ID)
		}
		seen[a.ID] = true

		if len(a.Fixes) == 0 {
			return fmt.Errorf("diagnose: repair action %q fixes no codes", a.ID)
		}
		for _, c := range a.Fixes {
			if !c.Known() {
				return fmt.Errorf("diagnose: repair action %q references unknown code %q", a.ID, c)
			}
		}

		kinds := make(map[string]bool, len(a.Snapshots))
		for _, s := range a.Snapshots {
			if s.Kind == "" {
				return fmt.Errorf("diagnose: repair action %q has an unnamed snapshot", a.ID)
			}
			kinds[s.Kind] = true
		}

		if a.Idempotent {
			if len(a.Snapshots) != 0 || len(a.Rollback) != 0 {
				return fmt.Errorf("diagnose: idempotent action %q must not declare snapshots or rollback", a.ID)
			}
		} else {
			if len(a.Snapshots) == 0 || len(a.Rollback) == 0 {
				return fmt.Errorf("diagnose: non-idempotent action %q must declare a snapshot and a rollback", a.ID)
			}
		}

		for _, step := range append(append([]Step{}, a.Apply...), a.Rollback...) {
			if !allowedOps[step.Op] {
				return fmt.Errorf("diagnose: repair action %q uses non-allowlisted op %q", a.ID, step.Op)
			}
			if k := step.Params[paramFromSnapshot]; k != "" && !kinds[k] {
				return fmt.Errorf("diagnose: repair action %q step %q reads snapshot %q that it never captures", a.ID, step.Op, k)
			}
		}
		if len(a.Apply) == 0 {
			return fmt.Errorf("diagnose: repair action %q has no apply steps", a.ID)
		}

		// Every recipe must carry at least one documented, allowlisted
		// postcondition so a successful apply is always verified against live
		// state before it is reported as fixed.
		if len(a.Postconditions) == 0 {
			return fmt.Errorf("diagnose: repair action %q declares no postconditions", a.ID)
		}
		pcSeen := make(map[PostconditionID]bool, len(a.Postconditions))
		for _, id := range a.Postconditions {
			if !allowedPostconditions[id] {
				return fmt.Errorf("diagnose: repair action %q uses non-allowlisted postcondition %q", a.ID, id)
			}
			if pcSeen[id] {
				return fmt.Errorf("diagnose: repair action %q repeats postcondition %q", a.ID, id)
			}
			pcSeen[id] = true
		}
	}
	return nil
}

// planSchema identifies the repair-plan contract version.
const planSchema = "ratelmesh.diagnose.repair-plan/v1"

// RepairPlan is an ordered set of candidate repairs for a set of findings.
// Plan always produces a dry run: preconditions are evaluated read-only and
// nothing is applied. Pass it to Execute to apply it through an Executor.
type RepairPlan struct {
	DryRun  bool
	Repairs []PlannedRepair

	redactor *Redactor
}

// PlannedRepair is one repair in a plan, with its preconditions evaluated.
type PlannedRepair struct {
	Action         RepairActionID
	Title          string
	Addresses      []Code
	Applicable     bool
	Preconditions  []PreconditionResult
	Snapshots      []SnapshotRequest
	Apply          []Step
	Rollback       []Step
	Postconditions []PostconditionID
}

// Plan performs a read-only dry run: it maps the findings onto catalogue
// actions, evaluates each action's preconditions against env, and returns an
// ordered plan without touching the system. An action appears at most once even
// if it addresses several findings.
func Plan(env *Env, findings []Finding) RepairPlan {
	present := make(map[Code]bool, len(findings))
	for _, f := range findings {
		present[f.Code] = true
	}

	var repairs []PlannedRepair
	for _, action := range repairCatalog {
		var addressed []Code
		for _, c := range action.Fixes {
			if present[c] {
				addressed = append(addressed, c)
			}
		}
		if len(addressed) == 0 {
			continue
		}
		sort.Slice(addressed, func(i, j int) bool { return addressed[i] < addressed[j] })

		applicable := true
		var pres []PreconditionResult
		for _, pc := range action.Preconditions {
			ok, detail := pc.check(env)
			if !ok {
				applicable = false
			}
			pres = append(pres, PreconditionResult{ID: pc.ID, Desc: pc.Desc, OK: ok, Detail: detail})
		}

		// Deep-clone every slice and every Step.Params map into the plan so a
		// caller that mutates any nested field of a returned PlannedRepair cannot
		// reach back into repairCatalog (which this loop ranges over directly).
		repairs = append(repairs, PlannedRepair{
			Action:         action.ID,
			Title:          action.Title,
			Addresses:      addressed,
			Applicable:     applicable,
			Preconditions:  pres,
			Snapshots:      cloneSnapshots(action.Snapshots),
			Apply:          cloneSteps(action.Apply),
			Rollback:       cloneSteps(action.Rollback),
			Postconditions: clonePostconditions(action.Postconditions),
		})
	}

	var red *Redactor
	if env != nil {
		red = env.Redactor
	}
	return RepairPlan{DryRun: true, Repairs: repairs, redactor: red}
}

// Applicable returns just the repairs whose preconditions all passed.
func (p RepairPlan) Applicable() []PlannedRepair {
	var out []PlannedRepair
	for _, r := range p.Repairs {
		if r.Applicable {
			out = append(out, r)
		}
	}
	return out
}

// Plan-serialisation wire structs.
type planWire struct {
	Schema  string        `json:"schema"`
	DryRun  bool          `json:"dry_run"`
	Repairs []plannedWire `json:"repairs"`
}

type plannedWire struct {
	Action         RepairActionID     `json:"action"`
	Title          string             `json:"title"`
	Addresses      []Code             `json:"addresses"`
	Applicable     bool               `json:"applicable"`
	Preconditions  []preconditionWire `json:"preconditions,omitempty"`
	Snapshots      []SnapshotRequest  `json:"snapshots,omitempty"`
	Apply          []Step             `json:"apply"`
	Rollback       []Step             `json:"rollback,omitempty"`
	Postconditions []PostconditionID  `json:"postconditions,omitempty"`
}

type preconditionWire struct {
	ID     string `json:"id"`
	Desc   string `json:"description"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// MarshalJSON renders the plan and passes it through the redactor as a final
// scrub, matching the report's no-raw-secrets guarantee.
func (p RepairPlan) MarshalJSON() ([]byte, error) {
	w := planWire{Schema: planSchema, DryRun: p.DryRun}
	for _, r := range p.Repairs {
		pw := plannedWire{
			Action:         r.Action,
			Title:          r.Title,
			Addresses:      r.Addresses,
			Applicable:     r.Applicable,
			Snapshots:      r.Snapshots,
			Apply:          r.Apply,
			Rollback:       r.Rollback,
			Postconditions: r.Postconditions,
		}
		for _, pc := range r.Preconditions {
			pw.Preconditions = append(pw.Preconditions, preconditionWire(pc))
		}
		w.Repairs = append(w.Repairs, pw)
	}
	raw, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	red := p.redactor
	if red == nil {
		red = NewRedactor(nil)
	}
	return red.RedactJSON(raw)
}

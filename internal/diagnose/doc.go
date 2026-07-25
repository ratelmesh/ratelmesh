// Package diagnose is the RatelMesh Network Doctor core: a dependency-light,
// standard-library-only engine that runs bounded, context-cancellable probes of
// a node's connectivity (Coordinator, Relay, EXIT, WireGuard, MTU, DNS, IPv4,
// IPv6, routes and sustained media reachability), turns the results into stable
// machine-readable findings, and derives declarative, allowlisted repair plans.
//
// # Design goals
//
//   - Bounded and cancellable. Every probe honours the caller's context and a
//     per-probe timeout; a hung or panicking probe can never wedge a run
//     (see Doctor.Run) and never leaks an unbounded number of goroutines.
//   - Privacy-preserving by construction. The support report is passed through a
//     deterministic Redactor as its final serialisation step, so raw secrets,
//     credentials, tokens, URLs/query strings, filesystem/user identifiers and
//     network identifiers cannot appear in the emitted JSON — even if a probe
//     author forgets to scrub a value (see Redactor and Report.MarshalJSON).
//   - No privileged execution here. This package plans repairs but never runs a
//     privileged system command. Probes reach the world only through injected
//     capability interfaces (Dialer, Resolver, HTTPDoer, PathMTUProber, Clock),
//     so platform adapters — and the privileged repair Executor — are supplied
//     later by the daemon without any test double leaking into product code.
//   - Deterministic. Findings, probe outcomes and report keys come out in a
//     stable order so two runs over identical inputs diff cleanly.
//
// # Repair safety
//
// Repairs are declarative data, not code. A RepairAction lists the allowlisted
// operations to apply, the state to snapshot first, the preconditions to verify
// and the explicit rollback steps to undo it. Plan performs a read-only dry run
// (evaluating preconditions, applying nothing); Execute later drives the plan
// through an injected Executor that Wade wires to the privileged primitives,
// with snapshot-capture-before-apply and automatic rollback on failure.
package diagnose

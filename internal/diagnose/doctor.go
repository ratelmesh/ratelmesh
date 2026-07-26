package diagnose

import (
	"context"
	"crypto/rand"
	"fmt"
	"strconv"
	"sync"
)

// Doctor runs a set of probes against a Snapshot and assembles a redacted
// report. It is safe for concurrent use and stateless between runs: all
// per-run state (the redactor, the shared Env) is built inside Run.
type Doctor struct {
	cfg    Config
	deps   Deps
	probes []Probe
	// probeSem bounds how many probe goroutines this Doctor may keep alive at
	// once. It is set once in New and never reassigned, so concurrent Run calls
	// share one immutable limiter with no data race. Tests inject a smaller one
	// via an Option instead of mutating any package-global.
	probeSem *semaphore
}

// Option customises a Doctor.
type Option func(*Doctor)

// WithProbes replaces the default probe set. It is the injection point tests
// use to add a hostile probe (one that blocks or panics) without any such
// double living in product code.
func WithProbes(probes ...Probe) Option {
	return func(d *Doctor) { d.probes = append([]Probe(nil), probes...) }
}

// New builds a Doctor. Missing config fields are filled from DefaultConfig and
// the probe set defaults to the full battery.
func New(cfg Config, deps Deps, opts ...Option) *Doctor {
	d := &Doctor{
		cfg:      cfg.withDefaults(),
		deps:     deps,
		probes:   defaultProbes(),
		probeSem: newSemaphore(defaultMaxLiveProbeGoroutines),
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// defaultProbes returns one instance of every probe, in canonical order.
func defaultProbes() []Probe {
	return []Probe{
		coordinatorProbe{},
		relayProbe{},
		exitProbe{},
		wireGuardProbe{},
		mtuProbe{},
		dnsProbe{},
		ipv4Probe{},
		ipv6Probe{},
		routesProbe{},
		mediaProbe{},
	}
}

// Run executes the selected probes concurrently, each under its own timeout and
// the caller's context, recovers panics, and returns a redacted Report. It
// always returns — a hung or panicking probe cannot wedge the run — and never
// leaves an unbounded number of goroutines behind.
func (d *Doctor) Run(ctx context.Context, snap Snapshot) Report {
	env := d.newEnv(snap)
	results := d.runProbes(ctx, env)
	return buildReport(env.Clock.Now(), results, env.Redactor)
}

// Diagnose runs the probes and, from the resulting findings, derives a
// dry-run RepairPlan in one call. The plan applies nothing; hand it to Execute
// with an injected Executor to act on it. This is the dry-run-first entry point.
func (d *Doctor) Diagnose(ctx context.Context, snap Snapshot) (Report, RepairPlan) {
	env := d.newEnv(snap)
	results := d.runProbes(ctx, env)
	report := buildReport(env.Clock.Now(), results, env.Redactor)

	// Seed the PLANNING environment with the path MTU the MTU probe just measured.
	// runProbes has fully joined its goroutines before returning, so env is no
	// longer shared; even so, we derive a copy and mutate only that, so the
	// authoritative measurement flows into planning without touching the run's
	// shared Snapshot (no concurrent mutation, no data race). Without this, Plan
	// would see Snapshot.ObservedPathMTU == 0 and the MTU-lowering repair could
	// never become applicable from the evidence this very run just gathered. Only a
	// strictly positive, in-bounds value parsed from the authoritative prober
	// evidence seeds it; a probe error/timeout leaves ObservedPathMTU untouched so
	// the repair stays inapplicable (fail closed).
	planEnv := env
	if mtu, ok := measuredPathMTU(results, d.cfg); ok {
		planEnv = env.withObservedPathMTU(mtu)
	}
	plan := Plan(planEnv, report.Findings)
	return report, plan
}

// measuredPathMTU extracts the actively measured path MTU from the MTU probe's
// RAW result (pre-redaction), when the active prober produced a usable, in-bounds
// measurement this run. It returns ok=false unless the MTU probe ran to
// completion AND recorded a strictly positive measured value that falls within
// the configured search window [SearchLow, SearchHigh]. It reads only the
// evMeasuredMTU evidence the probe itself wrote from the injected PathMTUProber —
// never a redacted string, a link-MTU fallback, or any externally supplied
// snapshot field — and bounds it, so a garbage, zero, or out-of-range value can
// never seed repair planning.
func measuredPathMTU(results []ProbeResult, cfg Config) (int, bool) {
	low, high := cfg.MTU.SearchLow, cfg.MTU.SearchHigh
	for _, r := range results {
		if r.Probe != ProbeMTU || r.Status != StatusCompleted {
			continue
		}
		for _, f := range r.Findings {
			raw, present := f.Evidence[evMeasuredMTU]
			if !present {
				continue
			}
			n, err := strconv.Atoi(raw)
			if err != nil || n <= 0 {
				continue
			}
			// The prober contract measures within [low, high]; anything outside the
			// configured window is not evidence we will trust to lower the MTU.
			if (low > 0 && n < low) || (high > 0 && n > high) {
				continue
			}
			return n, true
		}
	}
	return 0, false
}

// ExecutePlan applies plan through exec against a freshly captured, trusted
// execution environment built from snap. It is the safe entry point for acting
// on a plan: the plan's own Applicable/precondition claims are ignored and
// re-evaluated against snap, closing the plan-time/execute-time TOCTOU window,
// and each repair is re-validated against the authoritative catalogue recipe.
// Pass a snapshot captured immediately before execution, not the one the plan
// was planned from.
func (d *Doctor) ExecutePlan(ctx context.Context, snap Snapshot, plan RepairPlan, exec Executor) ExecutionReport {
	return Execute(ctx, d.newEnv(snap), plan, exec)
}

// newEnv builds the shared, read-only execution environment for one run,
// including a redactor seeded from the snapshot's sensitive values.
func (d *Doctor) newEnv(snap Snapshot) *Env {
	redactor := d.newRedactor(snap)
	return &Env{
		Snapshot: snap,
		Config:   d.cfg,
		Deps:     d.deps,
		Redactor: redactor,
		Clock:    d.deps.clock(),
	}
}

// withObservedPathMTU returns a shallow copy of env whose Snapshot records mtu as
// the observed path MTU, leaving the original env (which the probe goroutines
// shared) untouched. The copy carries a by-value Snapshot, so setting the scalar
// ObservedPathMTU touches only the copy; the Snapshot's slices are shared by
// reference but never mutated, so this introduces no data race.
func (e *Env) withObservedPathMTU(mtu int) *Env {
	cp := *e
	cp.Snapshot.ObservedPathMTU = mtu
	return &cp
}

// newRedactor builds the run's redactor. A caller-fixed salt is used verbatim
// (tests rely on this for byte-stable output). Otherwise a fresh random salt is
// drawn per run so fingerprints cannot be correlated or brute-forced across
// reports. If crypto/rand cannot supply that entropy, it fails closed to a
// sealed, non-fingerprinting redactor rather than fall back to a predictable
// salt that would make redaction fingerprints dictionary-verifiable.
func (d *Doctor) newRedactor(snap Snapshot) *Redactor {
	// Seed from both the snapshot identifiers and the run's configurable network
	// identifiers (connectivity targets, DNS query name) so an operator-overridden
	// internal host or domain cannot leak through a probe's evidence or error text.
	secrets := append(snap.sensitiveValues(), d.cfg.sensitiveValues()...)
	if d.cfg.RedactionSalt != nil {
		return NewRedactor(d.cfg.RedactionSalt, secrets...)
	}
	if salt, ok := randomSalt(); ok {
		return NewRedactor(salt, secrets...)
	}
	return newSealedRedactor(secrets...)
}

// runProbes runs the selected probes concurrently and returns their results.
// Each probe writes only its own result slot, so the run is race-free by
// construction and needs no lock.
func (d *Doctor) runProbes(ctx context.Context, env *Env) []ProbeResult {
	// Probes receive a copied view with every interface identifier tokenized.
	// This prevents evidence paths from exposing names carried by any current
	// interface-bearing snapshot field. Keep env itself raw: repair
	// planning/execution may need the actual platform identifiers and never
	// serializes the Snapshot directly.
	probeEnv := *env
	probeEnv.Snapshot = env.Snapshot.tokenizedReportIdentifiers(env.Redactor)
	env = &probeEnv

	selected, unknown := d.selectedProbes()
	// Any probe id the caller requested in Config.Probes that this Doctor does not
	// know about (a typo, a removed probe, or a wholly unknown id) yields a
	// deterministic probe.error framework finding — never silence. This fails
	// closed: a mis-typed or all-unknown Config.Probes (which would otherwise
	// filter to zero probes and produce a green "nothing ran" report) is forced to
	// a not-OK verdict, while a legitimate subset of known ids still runs exactly
	// that subset. The unknown results are appended in both the normal and the
	// nil-context paths so neither can leak an unwarranted green summary.
	unknownResults := d.unknownProbeResults(unknown, env)

	// Zero runnable probes must never read as a silent green "nothing ran" pass.
	// This happens when a Doctor is built with WithProbes() and no probes, or when
	// Config.Probes filters every known probe away with no leftover ids at all. (An
	// all-unknown Config.Probes is already handled above: those ids each become a
	// probe.error, so unknownResults is non-empty and forces not-OK.) When there is
	// genuinely nothing to run and nothing already failing closed, emit one
	// deterministic framework probe.error. This guard sits before the nil-context
	// branch so it holds for a nil context too, and it runs no probe.
	if len(selected) == 0 && len(unknownResults) == 0 {
		return []ProbeResult{d.noRunnableProbesResult(env)}
	}

	// A nil context would panic inside context.WithTimeout(nil, ...) in runOne.
	// Rather than invent a background context (which could run unbounded work) or
	// panic, fail closed: record a framework error for every selected probe so the
	// report is unmistakably not a clean pass and nothing runs. Doctor.Run and
	// Doctor.Diagnose both funnel through here, so both public entry points are
	// safe; Diagnose then derives a plan from these framework-error findings, which
	// map to no repair, yielding an empty (still dry-run) plan.
	if ctx == nil {
		return append(d.nilContextResults(selected, env), unknownResults...)
	}
	results := make([]ProbeResult, len(selected))
	var wg sync.WaitGroup
	for i := range selected {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = d.runOne(ctx, selected[i], env)
		}(i)
	}
	wg.Wait()
	return append(results, unknownResults...)
}

// unknownProbeResults builds a deterministic framework-error result for every
// probe id the caller requested that this Doctor does not implement. Each is a
// probe.error (SeverityWarning) finding, so any unknown id forces Summary.OK to
// false — a mis-typed or all-unknown Config.Probes can never resolve to a silent,
// green report. It runs no probe and spawns no goroutine.
func (d *Doctor) unknownProbeResults(unknown []ProbeID, env *Env) []ProbeResult {
	if len(unknown) == 0 {
		return nil
	}
	now := env.Clock.Now()
	results := make([]ProbeResult, 0, len(unknown))
	for _, id := range unknown {
		reportID := shareableProbeID(id, env.Redactor)
		res := ProbeResult{Probe: reportID, Status: StatusError, StartedAt: now}
		res.add(newFinding(reportID, CodeProbeError,
			fmt.Sprintf("probe %s was not run: unknown probe id requested in Config.Probes", reportID),
			map[string]string{"probe": string(reportID)}))
		results = append(results, res)
	}
	return results
}

// noRunnableProbesResult builds the single deterministic framework-error result
// used when a run has no probe to execute at all. It is a probe.error
// (SeverityWarning) so Summary.OK can never be true, and it spawns no goroutine.
func (d *Doctor) noRunnableProbesResult(env *Env) ProbeResult {
	res := ProbeResult{Probe: ProbeFramework, Status: StatusError, StartedAt: env.Clock.Now()}
	res.add(newFinding(ProbeFramework, CodeProbeError,
		"no probes were available to run",
		map[string]string{"probe": string(ProbeFramework)}))
	return res
}

// nilContextResults builds a framework-error result for every selected probe
// without running any probe or spawning any goroutine. It is the fail-closed
// response to a nil caller context: no probe executes, the report cannot read as
// a healthy pass, and no unbounded work is invented.
func (d *Doctor) nilContextResults(selected []Probe, env *Env) []ProbeResult {
	now := env.Clock.Now()
	results := make([]ProbeResult, len(selected))
	for i, p := range selected {
		id := p.ID()
		res := ProbeResult{Probe: id, Status: StatusError, StartedAt: now}
		res.add(newFinding(id, CodeProbeError,
			fmt.Sprintf("probe %s was not run: nil context", id),
			map[string]string{"probe": string(id)}))
		results[i] = res
	}
	return results
}

// selectedProbes returns the probes to run, honouring Config.Probes (a subset
// filter) while keeping canonical order, plus the deduplicated list of requested
// ids that match no known probe. An empty Config.Probes selects every probe and
// yields no unknowns. Unknown ids are returned in first-seen order so the
// resulting framework findings are deterministic.
func (d *Doctor) selectedProbes() (selected []Probe, unknown []ProbeID) {
	if len(d.cfg.Probes) == 0 {
		return d.probes, nil
	}
	known := make(map[ProbeID]bool, len(d.probes))
	for _, p := range d.probes {
		known[p.ID()] = true
	}
	want := make(map[ProbeID]bool, len(d.cfg.Probes))
	seenUnknown := make(map[ProbeID]bool)
	for _, id := range d.cfg.Probes {
		if known[id] {
			want[id] = true
			continue
		}
		if !seenUnknown[id] {
			seenUnknown[id] = true
			unknown = append(unknown, id)
		}
	}
	out := make([]Probe, 0, len(d.probes))
	for _, p := range d.probes {
		if want[p.ID()] {
			out = append(out, p)
		}
	}
	return out, unknown
}

// semaphore is a counting semaphore backed by a buffered channel. A slot is held
// for exactly as long as its holder goroutine is alive, so the number of live
// holders can never exceed the capacity.
type semaphore struct{ slots chan struct{} }

func newSemaphore(n int) *semaphore { return &semaphore{slots: make(chan struct{}, n)} }

// tryAcquire takes a slot without blocking, reporting whether one was free.
func (s *semaphore) tryAcquire() bool {
	select {
	case s.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

// release returns a previously acquired slot. It must be called exactly once per
// successful tryAcquire.
func (s *semaphore) release() { <-s.slots }

// defaultMaxLiveProbeGoroutines bounds how many probe goroutines a single Doctor
// may keep alive at once. A hostile Probe.Run that ignores its context keeps
// running after runOne stops waiting, orphaning its goroutine; capping the live
// count means repeated timed-out hostile probes can strand at most this many
// goroutines rather than an unbounded number. 64 is comfortably above any
// legitimate concurrency — a Doctor runs ~10 probes per Run, and a well-behaved
// probe releases its slot the instant it returns, so slots are only ever held
// briefly by in-flight probes — while still being a small, defensible ceiling on
// stuck orphans. The limiter is per-Doctor and immutable (see Doctor.probeSem),
// so no package-global mutation can race with a concurrent Run.
const defaultMaxLiveProbeGoroutines = 64

// runOne executes a single probe under a per-probe timeout derived from the
// caller's context, recovering panics and enforcing the deadline even if the
// probe itself misbehaves. A probe goroutine is spawned only if this Doctor's
// live-goroutine budget has a free slot, so a hostile probe that ignores ctx can
// never drive the goroutine count without bound.
func (d *Doctor) runOne(parent context.Context, p Probe, env *Env) ProbeResult {
	clock := env.Clock
	id := shareableProbeID(p.ID(), env.Redactor)
	start := clock.Now()

	stamp := func(res ProbeResult) ProbeResult {
		res.Probe = id
		res.StartedAt = start
		res.Duration = clock.Now().Sub(start)
		return res
	}

	// timedOut builds the framework timeout result. It is used both when we stop
	// waiting on the deadline and when a probe returns a result we cannot trust
	// because its context had already expired (see below).
	timedOut := func() ProbeResult {
		res := ProbeResult{Probe: id, Status: StatusTimeout}
		res.add(newFinding(id, CodeProbeTimeout,
			fmt.Sprintf("probe %s did not finish within its %s deadline", id, d.cfg.ProbeTimeout),
			map[string]string{"probe": string(id)}))
		return res
	}

	pctx, cancel := context.WithTimeout(parent, d.cfg.ProbeTimeout)
	defer cancel()

	// The limiter is the Doctor's own immutable instance; capture it locally so an
	// in-flight goroutine releases into the same semaphore it acquired.
	sem := d.probeSem
	if !sem.tryAcquire() {
		// The live-goroutine budget is exhausted (a flood of stuck orphans). Fail
		// this probe fast rather than spawn another leakable goroutine; the run
		// still returns promptly and records the refusal.
		res := ProbeResult{Probe: id, Status: StatusError}
		res.add(newFinding(id, CodeProbeError,
			fmt.Sprintf("probe %s was not run: live-probe goroutine limit reached", id),
			map[string]string{"probe": string(id)}))
		return stamp(res)
	}

	// A buffered channel lets the probe goroutine deliver its result and exit
	// even after we have stopped waiting, so a slow-but-cancellable probe never
	// leaks a goroutine.
	done := make(chan ProbeResult, 1)
	go func() {
		defer sem.release()
		defer func() {
			if recover() != nil {
				pr := ProbeResult{Probe: id, Status: StatusPanic}
				pr.add(newFinding(id, CodeProbePanic,
					fmt.Sprintf("probe %s panicked; payload withheld", id),
					map[string]string{"probe": string(id)}))
				done <- pr
			}
		}()
		r := p.Run(pctx, env)
		r.Probe = id
		if r.Status == "" {
			r.Status = StatusCompleted
		}
		done <- r
	}()

	select {
	case res := <-done:
		// A result and the deadline can become ready at the same instant; select
		// then chooses arbitrarily, so receiving a result does NOT prove the probe
		// finished within its budget. A probe that returns the moment its context
		// expires (a bare `<-ctx.Done(); return ProbeResult{}`) would otherwise be
		// stamped StatusCompleted with zero findings — a false-safe "healthy"
		// verdict for a check that never actually ran. If the context has already
		// fired, only trust a result the probe itself already classified as a
		// non-completed framework failure (panic, or a self-reported timeout);
		// anything that would read as "completed" is replaced with a framework
		// timeout so an expired context can never masquerade as a clean pass.
		if pctx.Err() != nil && !trustworthyOnExpiry(res.Status) {
			return stamp(timedOut())
		}
		return stamp(res)
	case <-pctx.Done():
		return stamp(timedOut())
	}
}

// trustworthyOnExpiry reports whether a probe-supplied status may be kept even
// though the probe's context had already expired when its result arrived. Only a
// status the probe explicitly set to a non-completed framework failure is
// trusted; a completed (or unset, which defaults to completed) status is not,
// because it cannot be distinguished from a probe that bailed out empty the
// instant its deadline fired.
func trustworthyOnExpiry(s ProbeStatus) bool {
	switch s {
	case StatusPanic, StatusTimeout, StatusError:
		return true
	default:
		return false
	}
}

// randRead is the entropy source for randomSalt. It is a var only so a test can
// force the crypto/rand failure path deterministically; production always uses
// crypto/rand.Read.
var randRead = rand.Read

// randomSalt returns a fresh 16-byte redaction salt read from crypto/rand,
// reporting ok=false if that entropy is unavailable. It deliberately offers no
// non-cryptographic fallback: a counter/clock/PID-derived salt is predictable,
// and a predictable salt makes redaction fingerprints dictionary-verifiable and
// correlatable across reports — "distinct" is not the same as "non-reversible".
// The caller fails closed to a sealed, non-fingerprinting redactor instead (see
// Doctor.newRedactor).
func randomSalt() ([]byte, bool) {
	b := make([]byte, 16)
	if _, err := randRead(b); err != nil {
		return nil, false
	}
	return b, true
}

package diagnose

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// This file holds every test double for the package. Per the injection design,
// no implementation of the capability interfaces lives outside _test.go except
// the real standard-library adapter in stdnet.go, so mocks never leak into
// product code.

// withProbeLimit overrides a Doctor's per-Doctor live-probe-goroutine limiter.
// It lives in test code because it is the only place that needs to shrink the
// bound; production uses the immutable default set in New. Because the limiter is
// per-Doctor, a test overriding it never mutates a package global and so cannot
// race with a concurrent Doctor run.
func withProbeLimit(n int) Option {
	return func(d *Doctor) { d.probeSem = newSemaphore(n) }
}

// --- clocks ------------------------------------------------------------------

// constClock returns a fixed time, so probe durations are 0 and reports are
// byte-deterministic across runs.
type constClock struct{ t time.Time }

func (c constClock) Now() time.Time { return c.t }

func fixedClock() constClock {
	return constClock{t: time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)}
}

// stepClock advances by a fixed step on every call, so a probe measuring an
// interval sees a deterministic elapsed time. It is concurrency-safe.
type stepClock struct {
	mu   sync.Mutex
	cur  time.Time
	step time.Duration
}

func newStepClock(step time.Duration) *stepClock {
	return &stepClock{cur: time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC), step: step}
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.cur
	c.cur = c.cur.Add(c.step)
	return now
}

// --- net.Conn stub -----------------------------------------------------------

type fakeConn struct{}

func (fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (fakeConn) Close() error                     { return nil }
func (fakeConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (fakeConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (fakeConn) SetDeadline(time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "fake" }

// --- Dialer ------------------------------------------------------------------

// fakeDialer connects successfully unless an address's host is listed in fail.
type fakeDialer struct {
	mu    sync.Mutex
	fail  map[string]error // keyed by dialed address; presence forces an error
	calls []string
}

func newFakeDialer() *fakeDialer { return &fakeDialer{fail: map[string]error{}} }

func (f *fakeDialer) failAddr(addr string) *fakeDialer {
	f.fail[addr] = errors.New("connection refused")
	return f
}

func (f *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.calls = append(f.calls, network+" "+address)
	err := f.fail[address]
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return fakeConn{}, nil
}

// alwaysFailDialer fails every dial with a timeout-classified error.
type alwaysFailDialer struct{}

func (alwaysFailDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, timeoutErr{}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// --- Resolver ----------------------------------------------------------------

type fakeResolver struct {
	addrs []netip.Addr
	err   error
}

func (f fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.addrs, nil
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func mustAddr(s string) netip.Addr     { return netip.MustParseAddr(s) }
func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// --- QUICProber --------------------------------------------------------------

type fakeQUIC struct {
	mu    sync.Mutex
	err   error
	calls int
	host  string
	port  int
}

func (f *fakeQUIC) ProbeQUIC(_ context.Context, host string, port int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.host = host
	f.port = port
	return f.err
}

type timeoutQUIC struct{}

func (timeoutQUIC) ProbeQUIC(ctx context.Context, _ string, _ int) error {
	<-ctx.Done()
	return ctx.Err()
}

// --- HTTPDoer ----------------------------------------------------------------

// mediaBody is a payload comfortably above minMediaSampleBytes (32 KiB) and
// below mediaReadLimit (64 KiB), so a fake 200/206 response counts as a real,
// sustained media transfer. Tests that must FAIL a transfer use a short body (or
// an empty one) instead, exercising the short/truncated-clean-EOF rejection.
var mediaBody = strings.Repeat("m", 40<<10)

type fakeHTTP struct {
	mu     sync.Mutex
	status int
	seq    []int // if non-empty, the status cycles through this per call
	idx    int
	body   string
	err    error
	calls  int
}

func newFakeHTTP(status int, body string) *fakeHTTP { return &fakeHTTP{status: status, body: body} }

func (f *fakeHTTP) Do(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.calls++
	st := f.status
	if len(f.seq) > 0 {
		st = f.seq[f.idx%len(f.seq)]
		f.idx++
	}
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return &http.Response{
		StatusCode: st,
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// errAfterReader yields `remaining` bytes across successive reads, then fails
// with err. It models a response body that streams a prefix and then breaks
// mid-chunk, so a media sample can look like it started before it stalls.
type errAfterReader struct {
	remaining int
	err       error
}

func (e *errAfterReader) Read(p []byte) (int, error) {
	if e.remaining <= 0 {
		return 0, e.err
	}
	n := len(p)
	if n > e.remaining {
		n = e.remaining
	}
	e.remaining -= n
	return n, nil
}

// midBodyErrHTTP returns a response whose status looks fine but whose body
// streams `prefix` bytes and then errors, to prove a mid-stream failure fails
// the media sample rather than counting as a transfer.
type midBodyErrHTTP struct {
	status int
	prefix int
	err    error
}

func (m midBodyErrHTTP) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: m.status,
		Body:       io.NopCloser(&errAfterReader{remaining: m.prefix, err: m.err}),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// countingCloser records how many times a body is closed. The media probe runs
// its samples sequentially in one goroutine, so a plain counter needs no lock.
type countingCloser struct {
	io.Reader
	closes *int
}

func (c countingCloser) Close() error { *c.closes++; return nil }

// closeCountingHTTP hands back a fresh body per call that records its Close
// calls through a shared counter, to prove the sampler always closes the body.
type closeCountingHTTP struct {
	status int
	body   string
	closes *int
}

func (c closeCountingHTTP) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: c.status,
		Body:       countingCloser{Reader: strings.NewReader(c.body), closes: c.closes},
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// --- PathMTUProber ------------------------------------------------------------

type fakeMTU struct {
	mtu int
	err error
}

func (f fakeMTU) ProbeMTU(ctx context.Context, dst string, low, high int) (int, error) {
	return f.mtu, f.err
}

// recordingMTU records every dst it is asked to probe, so a test can assert which
// path the MTU probe measured against (and prove it is never the coordinator). It
// returns a fixed mtu/err.
type recordingMTU struct {
	mu   sync.Mutex
	mtu  int
	err  error
	dsts []string
}

func (r *recordingMTU) ProbeMTU(ctx context.Context, dst string, low, high int) (int, error) {
	r.mu.Lock()
	r.dsts = append(r.dsts, dst)
	r.mu.Unlock()
	return r.mtu, r.err
}

func (r *recordingMTU) lastDst() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.dsts) == 0 {
		return ""
	}
	return r.dsts[len(r.dsts)-1]
}

func (r *recordingMTU) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.dsts)
}

// --- Executor ----------------------------------------------------------------

// fakeExecutor records what it was asked to do and can be told to fail a
// specific snapshot kind or a specific apply op. Postcondition checks pass by
// default so ordinary apply tests reach RepairApplied; a test can force a
// specific postcondition to report unmet, error, or block until its context
// deadline fires.
type fakeExecutor struct {
	mu            sync.Mutex
	captured      []string
	applied       []RepairOp
	checked       []PostconditionID
	snapshotFail  string            // Kind whose capture fails
	applyFail     RepairOp          // op whose apply fails
	failOps       map[RepairOp]bool // any op in this set fails (covers rollback ops too)
	postFail      PostconditionID   // postcondition that reports unmet (ok=false)
	postErr       PostconditionID   // postcondition whose check returns an error
	postBlock     PostconditionID   // postcondition that blocks until ctx is done
	sawCancelled  bool
	sawUncanceled bool

	// Deterministic timing hooks. onCapture fires at the end of each successful
	// CaptureSnapshot; onApply fires at the start of each Apply (before the ctx
	// check). A test uses these to cancel the caller's context at an exact point —
	// e.g. after snapshots but before the first apply — without racy sleeps.
	onCapture func()
	onApply   func()

	// MTU-snapshot controls. The "mtu" snapshot carries the live link/path MTU the
	// execute-time guard revalidates against. Zero means "safe default" (1500 link,
	// 1400 path, both well above the 1280 floor) so ordinary apply tests reach
	// RepairApplied; a regression can drop either below the floor or omit it.
	mtuLinkCapture int
	mtuPathCapture int
	mtuOmitLink    bool
	mtuOmitPath    bool
}

func (f *fakeExecutor) CaptureSnapshot(ctx context.Context, req SnapshotRequest) (SnapshotData, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.captured = append(f.captured, req.Kind)
	if req.Kind == f.snapshotFail {
		return SnapshotData{}, errors.New("capture failed")
	}
	vals := map[string]string{"prior": "value"}
	if req.Kind == mtuSnapshotKind {
		link := f.mtuLinkCapture
		if link == 0 {
			link = 1500
		}
		path := f.mtuPathCapture
		if path == 0 {
			path = 1400
		}
		if !f.mtuOmitLink {
			vals[snapKeyLinkMTU] = strconv.Itoa(link)
		}
		if !f.mtuOmitPath {
			vals[snapKeyPathMTU] = strconv.Itoa(path)
		}
	}
	data := SnapshotData{Kind: req.Kind, Values: vals}
	if f.onCapture != nil {
		f.onCapture()
	}
	return data, nil
}

func (f *fakeExecutor) Apply(ctx context.Context, step Step, snapshots []SnapshotData) error {
	if f.onApply != nil {
		f.onApply()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, step.Op)
	if ctx.Err() != nil {
		f.sawCancelled = true
	} else {
		f.sawUncanceled = true
	}
	if step.Op == f.applyFail || f.failOps[step.Op] {
		return errors.New("apply failed")
	}
	return nil
}

func (f *fakeExecutor) CheckPostcondition(ctx context.Context, id PostconditionID, _ []SnapshotData) (bool, error) {
	f.mu.Lock()
	f.checked = append(f.checked, id)
	block := f.postBlock == id
	f.mu.Unlock()
	if block {
		<-ctx.Done() // honours the deadline but not caller cancellation
		return false, ctx.Err()
	}
	if f.postErr == id {
		return false, errors.New("postcondition unobservable")
	}
	if f.postFail == id {
		return false, nil
	}
	return true, nil
}

// --- probes used to exercise the runner --------------------------------------

// blockingProbe blocks until its context is cancelled, then returns. It exists
// only to prove the runner enforces the per-probe deadline and does not leak.
type blockingProbe struct{ id ProbeID }

func (b blockingProbe) ID() ProbeID { return b.id }
func (b blockingProbe) Run(ctx context.Context, env *Env) ProbeResult {
	<-ctx.Done()
	return ProbeResult{Probe: b.id}
}

// panicProbe always panics, to prove the runner recovers and keeps going.
type panicProbe struct{ id ProbeID }

func (p panicProbe) ID() ProbeID { return p.id }
func (p panicProbe) Run(ctx context.Context, env *Env) ProbeResult {
	panic("boom")
}

// staticProbe returns a fixed finding, to prove sibling probes still run when
// another probe fails.
type staticProbe struct {
	id   ProbeID
	code Code
}

func (s staticProbe) ID() ProbeID { return s.id }
func (s staticProbe) Run(ctx context.Context, env *Env) ProbeResult {
	res := ProbeResult{Probe: s.id}
	res.add(newFinding(s.id, s.code, "static", nil))
	return res
}

// --- snapshot builders -------------------------------------------------------

// healthySnapshot returns a snapshot where every probe should report OK when
// paired with a permissive fakeDialer/resolver/HTTP.
func healthySnapshot() Snapshot {
	now := fixedClock().t
	media := Endpoint{Label: "video-canary", Host: "video.example.net", Port: 443, Scheme: "https", HealthPath: "/chunk"}
	return Snapshot{
		Coordinator: Endpoint{Label: "coordinator", Host: "coord.example.net", Port: 443, Scheme: "https", HealthPath: "/healthz"},
		Relays:      []Endpoint{{Label: "relay-1", Host: "relay1.example.net", Port: 443}},
		Exit: &ExitState{
			PeerPublicKey: "cGVlcnB1YmxpY2tleQ==",
			LastHandshake: now.Add(-10 * time.Second),
			RoutePresent:  true,
			EgressCanary:  &media,
		},
		WireGuard: WireGuardState{
			Interface: "utun7",
			Up:        true,
			LinkMTU:   1280,
			Peers: []PeerStatus{
				{PublicKey: "cGVlcm9uZQ==", LastHandshake: now.Add(-5 * time.Second)},
				{PublicKey: "cGVlcnR3bw==", LastHandshake: now.Add(-8 * time.Second), IsExit: true},
			},
		},
		Addresses: []InterfaceAddr{
			{Interface: "en0", Family: FamilyV4, Addr: netip.MustParseAddr("192.168.1.20")},
			{Interface: "en0", Family: FamilyV6, Addr: netip.MustParseAddr("2001:db8::20")},
		},
		Routes: []Route{
			{Destination: netip.MustParsePrefix("0.0.0.0/1"), Interface: "utun7", ViaTunnel: true},
			{Destination: netip.MustParsePrefix("128.0.0.0/1"), Interface: "utun7", ViaTunnel: true},
			{Destination: netip.MustParsePrefix("::/0"), Interface: "utun7", ViaTunnel: true},
		},
		DNS:          DNSState{Servers: addrs("100.100.100.100"), ViaTunnel: true},
		MediaTargets: []Endpoint{media},
		ExitActive:   true,
	}
}

// permissiveDeps returns deps where every network operation succeeds.
func permissiveDeps(clock Clock) Deps {
	return Deps{
		Dialer:   newFakeDialer(),
		Resolver: fakeResolver{addrs: addrs("93.184.216.34")}, // a public address (example.com)
		HTTP:     newFakeHTTP(200, mediaBody),
		MTU:      fakeMTU{mtu: 1280},
		Clock:    clock,
	}
}

// fixedSaltConfig returns a config with a fixed redaction salt so redaction and
// therefore report bytes are deterministic. Media has no inter-sample sleep so
// tests run instantly.
func fixedSaltConfig() Config {
	c := DefaultConfig()
	c.RedactionSalt = []byte("test-salt-deterministic")
	c.Media.Interval = 0
	return c
}

// envWith builds a read-only Env for exercising a probe directly, defaulting
// the config and seeding a redactor.
func envWith(snap Snapshot, deps Deps, cfg Config) *Env {
	c := cfg.withDefaults()
	if c.RedactionSalt == nil {
		c.RedactionSalt = []byte("salt")
	}
	return &Env{
		Snapshot: snap,
		Config:   c,
		Deps:     deps,
		Redactor: NewRedactor(c.RedactionSalt, append(snap.sensitiveValues(), c.sensitiveValues()...)...),
		Clock:    deps.clock(),
	}
}

// directEnv builds an Env with the standard fixed-salt config.
func directEnv(snap Snapshot, deps Deps) *Env {
	return envWith(snap, deps, fixedSaltConfig())
}

package remoteservice

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type counterReader struct {
	mu   sync.Mutex
	next byte
}

func (r *counterReader) Read(buffer []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next++
	for index := range buffer {
		buffer[index] = r.next
	}
	return len(buffer), nil
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

type fakePresence struct {
	err   error
	wait  bool
	gate  <-chan struct{}
	ready chan<- struct{}
	calls atomic.Int32
}

func (p *fakePresence) ConfirmServiceStart(ctx context.Context, _ Target) error {
	p.calls.Add(1)
	if p.ready != nil {
		p.ready <- struct{}{}
	}
	if p.gate != nil {
		select {
		case <-p.gate:
			return p.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if p.wait {
		<-ctx.Done()
		return ctx.Err()
	}
	return p.err
}

type fakeBackend struct {
	mu sync.Mutex

	state         ServiceState
	health        Health
	captureErr    error
	startErr      error
	detectErr     error
	rollbackErr   error
	startChanged  bool
	captureWait   bool
	startWait     bool
	detectWait    bool
	rollbackWait  bool
	nilAfterWait  bool
	conflict      bool
	startGate     chan struct{}
	startEntered  chan struct{}
	revision      ServiceRevision
	active        int
	maxActive     int
	captureCalls  int
	startCalls    int
	detectCalls   int
	rollbackCalls int
}

func (b *fakeBackend) Capture(ctx context.Context, _ Target) (ServiceState, error) {
	b.mu.Lock()
	b.captureCalls++
	state, err, wait := b.state, b.captureErr, b.captureWait
	b.mu.Unlock()
	if wait {
		<-ctx.Done()
		if b.nilAfterWait {
			return state, nil
		}
		return ServiceState{}, ctx.Err()
	}
	return state, err
}

func (b *fakeBackend) Start(ctx context.Context, _ Target, permit StartPermit) (ChangeReceipt, error) {
	b.mu.Lock()
	b.startCalls++
	b.active++
	if b.active > b.maxActive {
		b.maxActive = b.active
	}
	changed, err, wait, gate, entered := b.startChanged, b.startErr, b.startWait, b.startGate, b.startEntered
	revision := b.revision
	if revision == (ServiceRevision{}) {
		revision[0] = 1
	}
	var receipt ChangeReceipt
	if changed {
		var ownership [32]byte
		ownership[0] = 1
		receipt = permit.CommitOwned(revision, ownership)
	}
	b.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	defer func() {
		b.mu.Lock()
		b.active--
		if changed {
			b.state.Running = true
			b.revision = revision
		}
		b.mu.Unlock()
	}()
	if wait {
		<-ctx.Done()
		if b.nilAfterWait {
			return receipt, nil
		}
		return receipt, ctx.Err()
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return receipt, ctx.Err()
		}
	}
	return receipt, err
}

func (b *fakeBackend) Detect(ctx context.Context, _ Target) (Health, error) {
	b.mu.Lock()
	b.detectCalls++
	health, err, wait := b.health, b.detectErr, b.detectWait
	b.mu.Unlock()
	if wait {
		<-ctx.Done()
		if b.nilAfterWait {
			return health, nil
		}
		return Health{}, ctx.Err()
	}
	return health, err
}

func (b *fakeBackend) Rollback(ctx context.Context, target Target, pre ServiceState, receipt ChangeReceipt) error {
	b.mu.Lock()
	b.rollbackCalls++
	err, wait, conflict, current := b.rollbackErr, b.rollbackWait, b.conflict, b.revision
	b.mu.Unlock()
	if wait {
		<-ctx.Done()
		if b.nilAfterWait {
			return nil
		}
		return ctx.Err()
	}
	if conflict {
		current[0]++
	}
	if !receipt.AuthorizesRollback(target, pre, current) {
		return ErrRollbackConflict
	}
	b.mu.Lock()
	b.state = pre
	b.revision = ServiceRevision{}
	b.mu.Unlock()
	return err
}

func targetFor(platform Platform, service ServiceKind) Target {
	var id DeviceID
	id[0] = 7
	return Target{Device: id, Platform: platform, Service: service}
}

func testConfig() Config {
	return Config{
		ConfirmationTTL:     time.Minute,
		ConfirmationTimeout: 50 * time.Millisecond,
		CaptureTimeout:      50 * time.Millisecond,
		StartTimeout:        50 * time.Millisecond,
		VerifyTimeout:       50 * time.Millisecond,
		RollbackTimeout:     50 * time.Millisecond,
		MaxConfirmations:    16,
		MaxTransactions:     8,
	}
}

func testConfirmer(t *testing.T, presence LocalPresence, clk clock) *Confirmer {
	t.Helper()
	confirmer, err := newConfirmer(presence, &counterReader{}, clk, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	return confirmer
}

func confirmedRequest(t *testing.T, confirmer *Confirmer, target Target) Request {
	t.Helper()
	token, err := confirmer.Confirm(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	return Request{Target: target, Operation: OperationEnsureRunning, Confirmation: token}
}

func healthy() Health {
	return Health{Running: true, Listening: true, Healthy: true, IdentityVerified: true}
}

func TestConfirmationExpiryReplayAndBinding(t *testing.T) {
	now := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, now)
	target := targetFor(PlatformLinux, ServiceSSH)

	expiring := confirmedRequest(t, confirmer, target)
	now.advance(time.Minute)
	if err := confirmer.consume(target, expiring.Confirmation); !IsCode(err, CodeConfirmationExpired) {
		t.Fatalf("expired error = %v", err)
	}

	bound := confirmedRequest(t, confirmer, target)
	wrong := target
	wrong.Device[1] = 9
	if err := confirmer.consume(wrong, bound.Confirmation); !IsCode(err, CodeConfirmationInvalid) {
		t.Fatalf("wrong binding error = %v", err)
	}
	if err := confirmer.consume(target, bound.Confirmation); err != nil {
		t.Fatalf("correct binding after attack: %v", err)
	}
	if err := confirmer.consume(target, bound.Confirmation); !IsCode(err, CodeConfirmationReplay) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestRestartInvalidatesConfirmation(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	first := testConfirmer(t, &fakePresence{}, clk)
	target := targetFor(PlatformLinux, ServiceSSH)
	request := confirmedRequest(t, first, target)
	restarted := testConfirmer(t, &fakePresence{}, clk)
	if err := restarted.consume(target, request.Confirmation); !IsCode(err, CodeConfirmationInvalid) {
		t.Fatalf("restart error = %v", err)
	}
}

func TestConfirmationRequiresLocalPresenceAndIsBounded(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	denied := testConfirmer(t, &fakePresence{err: errors.New("no")}, clk)
	if _, err := denied.Confirm(context.Background(), targetFor(PlatformLinux, ServiceSSH)); !IsCode(err, CodeConfirmationDenied) {
		t.Fatalf("denied error = %v", err)
	}
	timeout := testConfirmer(t, &fakePresence{wait: true}, clk)
	if _, err := timeout.Confirm(context.Background(), targetFor(PlatformLinux, ServiceSSH)); !IsCode(err, CodeTimeout) {
		t.Fatalf("timeout error = %v", err)
	}
}

func TestConfirmationCapacityIsBounded(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	config := testConfig()
	config.MaxConfirmations = 1
	confirmer, err := newConfirmer(&fakePresence{}, &counterReader{}, clk, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := confirmer.Confirm(context.Background(), targetFor(PlatformLinux, ServiceSSH)); err != nil {
		t.Fatal(err)
	}
	if _, err := confirmer.Confirm(context.Background(), targetFor(PlatformLinux, ServiceSSH)); !IsCode(err, CodeConfirmationCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	clk.advance(time.Minute)
	if _, err := confirmer.Confirm(context.Background(), targetFor(PlatformLinux, ServiceSSH)); err != nil {
		t.Fatalf("expired record did not free capacity: %v", err)
	}
}

func TestConfirmationCapacityIncludesInflightPrompts(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	config := testConfig()
	config.MaxConfirmations = 1
	gate := make(chan struct{})
	ready := make(chan struct{}, 1)
	presence := &fakePresence{gate: gate, ready: ready}
	confirmer, err := newConfirmer(presence, &counterReader{}, clk, config)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, confirmErr := confirmer.Confirm(context.Background(), targetFor(PlatformLinux, ServiceSSH))
		done <- confirmErr
	}()
	<-ready
	if _, err := confirmer.Confirm(context.Background(), targetFor(PlatformLinux, ServiceSSH)); !IsCode(err, CodeConfirmationCapacity) {
		t.Fatalf("in-flight capacity error = %v", err)
	}
	if presence.calls.Load() != 1 {
		t.Fatalf("local UI prompts = %d, want 1", presence.calls.Load())
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDeniedPromptReleasesCapacityReservation(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	config := testConfig()
	config.MaxConfirmations = 1
	presence := &fakePresence{err: errors.New("denied")}
	confirmer, err := newConfirmer(presence, &counterReader{}, clk, config)
	if err != nil {
		t.Fatal(err)
	}
	target := targetFor(PlatformLinux, ServiceSSH)
	if _, err := confirmer.Confirm(context.Background(), target); !IsCode(err, CodeConfirmationDenied) {
		t.Fatalf("denial error = %v", err)
	}
	presence.err = nil
	if _, err := confirmer.Confirm(context.Background(), target); err != nil {
		t.Fatalf("denial leaked reservation: %v", err)
	}
}

func TestEnsureRunningStarted(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	backend := &fakeBackend{startChanged: true, health: healthy()}
	manager, err := NewManager(backend, confirmer, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.EnsureRunning(context.Background(), confirmedRequest(t, confirmer, targetFor(PlatformLinux, ServiceSSH)))
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != OutcomeStarted || result.Rollback {
		t.Fatalf("result = %+v", result)
	}
}

func TestAlreadyRunningIsIdempotentAndNeverRolledBack(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	backend := &fakeBackend{state: ServiceState{Running: true, Enabled: true}, health: healthy()}
	manager, _ := NewManager(backend, confirmer, testConfig())
	result, err := manager.EnsureRunning(context.Background(), confirmedRequest(t, confirmer, targetFor(PlatformMacOS, ServiceSSH)))
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != OutcomeAlreadyRunning {
		t.Fatalf("result = %+v", result)
	}
	if backend.startCalls != 0 || backend.rollbackCalls != 0 {
		t.Fatalf("start=%d rollback=%d", backend.startCalls, backend.rollbackCalls)
	}
}

func TestAlreadyRunningUnhealthyIsNeverChanged(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	backend := &fakeBackend{
		state:  ServiceState{Running: true, Enabled: true},
		health: Health{Running: true, Listening: true},
	}
	manager, _ := NewManager(backend, confirmer, testConfig())
	_, err := manager.EnsureRunning(context.Background(), confirmedRequest(t, confirmer, targetFor(PlatformWindows, ServiceRDP)))
	if !IsCode(err, CodeAlreadyRunningUnhealthy) {
		t.Fatalf("error = %v", err)
	}
	if backend.startCalls != 0 || backend.rollbackCalls != 0 {
		t.Fatalf("start=%d rollback=%d", backend.startCalls, backend.rollbackCalls)
	}
}

func TestFailedVerifyRollsBackOnlyStartedService(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	backend := &fakeBackend{startChanged: true, health: Health{Running: true}}
	manager, _ := NewManager(backend, confirmer, testConfig())
	result, err := manager.EnsureRunning(context.Background(), confirmedRequest(t, confirmer, targetFor(PlatformWindows, ServiceRDP)))
	if !IsCode(err, CodeVerifyFailed) || result.Code != OutcomeRolledBack || !result.Rollback {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if backend.rollbackCalls != 1 {
		t.Fatalf("rollback calls = %d", backend.rollbackCalls)
	}
}

func TestRollbackFailureIsReported(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	backend := &fakeBackend{
		startChanged: true,
		detectErr:    errors.New("probe"),
		rollbackErr:  errors.New("rollback"),
	}
	manager, _ := NewManager(backend, confirmer, testConfig())
	result, err := manager.EnsureRunning(context.Background(), confirmedRequest(t, confirmer, targetFor(PlatformWindows, ServiceSSH)))
	var serviceErr *Error
	if !errors.As(err, &serviceErr) || serviceErr.Code != CodeVerifyFailed || serviceErr.RollbackCode != CodeRollbackFailed {
		t.Fatalf("result=%+v err=%#v", result, err)
	}
	if result.Code != OutcomeRollbackFailed || !result.Rollback {
		t.Fatalf("result = %+v", result)
	}
}

func TestTimeoutsAndRollbackTimeout(t *testing.T) {
	for _, test := range []struct {
		name         string
		backend      *fakeBackend
		want         ErrorCode
		rollback     bool
		rollbackCode ErrorCode
	}{
		{name: "capture", backend: &fakeBackend{captureWait: true}, want: CodeTimeout},
		{
			name:    "start and rollback",
			backend: &fakeBackend{startWait: true, startChanged: true, rollbackWait: true},
			want:    CodeTimeout, rollback: true, rollbackCode: CodeTimeout,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			clk := &fakeClock{now: time.Unix(100, 0)}
			confirmer := testConfirmer(t, &fakePresence{}, clk)
			manager, _ := NewManager(test.backend, confirmer, testConfig())
			result, err := manager.EnsureRunning(context.Background(), confirmedRequest(t, confirmer, targetFor(PlatformLinux, ServiceSSH)))
			var serviceErr *Error
			if !errors.As(err, &serviceErr) || serviceErr.Code != test.want {
				t.Fatalf("result=%+v err=%#v", result, err)
			}
			if result.Rollback != test.rollback || serviceErr.RollbackCode != test.rollbackCode {
				t.Fatalf("result=%+v error=%+v", result, serviceErr)
			}
		})
	}
}

func TestExpiredOperationContextOverridesNilBackendError(t *testing.T) {
	tests := []struct {
		name         string
		backend      *fakeBackend
		want         ErrorCode
		rollback     bool
		rollbackCode ErrorCode
	}{
		{
			name:    "capture",
			backend: &fakeBackend{captureWait: true, nilAfterWait: true},
			want:    CodeTimeout,
		},
		{
			name: "start preserves receipt and rolls back",
			backend: &fakeBackend{
				startWait:    true,
				startChanged: true,
				nilAfterWait: true,
			},
			want: CodeTimeout, rollback: true,
		},
		{
			name: "detect",
			backend: &fakeBackend{
				startChanged: true,
				detectWait:   true,
				nilAfterWait: true,
			},
			want: CodeTimeout, rollback: true,
		},
		{
			name: "rollback",
			backend: &fakeBackend{
				startChanged: true,
				detectErr:    errors.New("verify"),
				rollbackWait: true,
				nilAfterWait: true,
			},
			want: CodeVerifyFailed, rollback: true, rollbackCode: CodeTimeout,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clk := &fakeClock{now: time.Unix(100, 0)}
			confirmer := testConfirmer(t, &fakePresence{}, clk)
			manager, _ := NewManager(test.backend, confirmer, testConfig())
			result, err := manager.EnsureRunning(context.Background(), confirmedRequest(t, confirmer, targetFor(PlatformLinux, ServiceSSH)))
			var serviceErr *Error
			if !errors.As(err, &serviceErr) || serviceErr.Code != test.want {
				t.Fatalf("result=%+v error=%#v", result, err)
			}
			if result.Rollback != test.rollback || serviceErr.RollbackCode != test.rollbackCode {
				t.Fatalf("result=%+v error=%+v", result, serviceErr)
			}
			if test.rollbackCode != "" && result.Code != OutcomeRollbackFailed {
				t.Fatalf("expired rollback reported success: %+v", result)
			}
		})
	}
}

func TestRollbackConflictIsStableFailure(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	backend := &fakeBackend{
		startChanged: true,
		detectErr:    errors.New("verify"),
		conflict:     true,
	}
	manager, _ := NewManager(backend, confirmer, testConfig())
	result, err := manager.EnsureRunning(context.Background(), confirmedRequest(t, confirmer, targetFor(PlatformWindows, ServiceRDP)))
	var serviceErr *Error
	if !errors.As(err, &serviceErr) || serviceErr.RollbackCode != CodeRollbackConflict {
		t.Fatalf("result=%+v error=%#v", result, err)
	}
	if result.Code != OutcomeRollbackFailed || !result.Rollback {
		t.Fatalf("conflict result = %+v", result)
	}
}

func TestReceiptExactBindingAndReplay(t *testing.T) {
	target := targetFor(PlatformLinux, ServiceSSH)
	before := ServiceState{Enabled: true}
	var nonce [32]byte
	nonce[0] = 9
	var revision ServiceRevision
	revision[0] = 4
	permit := StartPermit{nonce: nonce, target: target, before: before}
	var ownership [32]byte
	ownership[0] = 8
	receipt := permit.CommitOwned(revision, ownership)
	if !receipt.Changed() || !receipt.AuthorizesRollback(target, before, revision) {
		t.Fatal("valid receipt was rejected")
	}
	wrongTarget := target
	wrongTarget.Device[1] = 1
	if receipt.AuthorizesRollback(wrongTarget, before, revision) {
		t.Fatal("receipt authorized wrong target")
	}
	wrongBefore := before
	wrongBefore.Enabled = false
	if receipt.AuthorizesRollback(target, wrongBefore, revision) {
		t.Fatal("receipt authorized wrong pre-state")
	}
	wrongRevision := revision
	wrongRevision[1] = 1
	if receipt.AuthorizesRollback(target, before, wrongRevision) {
		t.Fatal("receipt authorized external state revision")
	}

	backend := &fakeBackend{revision: revision}
	if err := backend.Rollback(context.Background(), target, before, receipt); err != nil {
		t.Fatal(err)
	}
	if err := backend.Rollback(context.Background(), target, before, receipt); !errors.Is(err, ErrRollbackConflict) {
		t.Fatalf("receipt replay error = %v", err)
	}
}

func TestConcurrentRequestsSerializePerService(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	backend := &fakeBackend{startChanged: true, health: healthy(), startGate: gate, startEntered: entered}
	manager, _ := NewManager(backend, confirmer, testConfig())
	target := targetFor(PlatformLinux, ServiceSSH)
	first := confirmedRequest(t, confirmer, target)
	second := confirmedRequest(t, confirmer, target)
	results := make(chan error, 2)
	go func() {
		_, err := manager.EnsureRunning(context.Background(), first)
		results <- err
	}()
	<-entered
	go func() {
		_, err := manager.EnsureRunning(context.Background(), second)
		results <- err
	}()
	close(gate)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.maxActive != 1 || backend.startCalls != 1 {
		t.Fatalf("max active=%d starts=%d", backend.maxActive, backend.startCalls)
	}
}

func TestConfirmationCannotExpireWhileQueuedForServiceLock(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	backend := &fakeBackend{startChanged: true, health: healthy(), startGate: gate, startEntered: entered}
	manager, _ := NewManager(backend, confirmer, testConfig())
	target := targetFor(PlatformLinux, ServiceSSH)
	first := confirmedRequest(t, confirmer, target)
	second := confirmedRequest(t, confirmer, target)
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)

	go func() {
		_, err := manager.EnsureRunning(context.Background(), first)
		firstDone <- err
	}()
	<-entered
	go func() {
		_, err := manager.EnsureRunning(context.Background(), second)
		secondDone <- err
	}()

	deadline := time.Now().Add(time.Second)
	for {
		manager.locksMu.Lock()
		lock := manager.locks[target]
		waiting := lock != nil && lock.refs == 2
		manager.locksMu.Unlock()
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("second request did not queue for target lock")
		}
		runtime.Gosched()
	}

	clk.advance(testConfig().ConfirmationTTL)
	close(gate)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; !IsCode(err, CodeConfirmationExpired) {
		t.Fatalf("queued expired confirmation error = %v", err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.startCalls != 1 {
		t.Fatalf("expired queued confirmation caused %d starts, want 1", backend.startCalls)
	}
}

func TestInvalidTokensNeverAllocateKeyedLocks(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	manager, _ := NewManager(&fakeBackend{}, confirmer, testConfig())
	for index := range 200 {
		target := targetFor(PlatformLinux, ServiceSSH)
		target.Device[1] = byte(index + 1)
		request := Request{
			Target:       target,
			Operation:    OperationEnsureRunning,
			Confirmation: ConfirmationToken{byte(index + 1)},
		}
		if _, err := manager.EnsureRunning(context.Background(), request); !IsCode(err, CodeConfirmationInvalid) {
			t.Fatalf("request %d error = %v", index, err)
		}
	}
	manager.locksMu.Lock()
	defer manager.locksMu.Unlock()
	if len(manager.locks) != 0 {
		t.Fatalf("invalid tokens retained %d keyed locks", len(manager.locks))
	}
}

func TestInvalidConfirmationDoesNotWaitForBusyServiceLock(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	backend := &fakeBackend{startChanged: true, health: healthy(), startGate: gate, startEntered: entered}
	manager, _ := NewManager(backend, confirmer, testConfig())
	target := targetFor(PlatformLinux, ServiceSSH)
	first := confirmedRequest(t, confirmer, target)
	firstDone := make(chan error, 1)
	go func() {
		_, err := manager.EnsureRunning(context.Background(), first)
		firstDone <- err
	}()
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := manager.EnsureRunning(ctx, Request{
		Target:       target,
		Operation:    OperationEnsureRunning,
		Confirmation: ConfirmationToken{1},
	})
	if !IsCode(err, CodeConfirmationInvalid) {
		t.Fatalf("invalid confirmation queued behind target lock: %v", err)
	}

	close(gate)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestBusyServiceWaitIsCancelableAndLockIsPruned(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	backend := &fakeBackend{startChanged: true, health: healthy(), startGate: gate, startEntered: entered}
	config := testConfig()
	config.StartTimeout = time.Second
	manager, _ := NewManager(backend, confirmer, config)
	target := targetFor(PlatformLinux, ServiceSSH)
	first := confirmedRequest(t, confirmer, target)
	second := confirmedRequest(t, confirmer, target)
	firstDone := make(chan error, 1)
	go func() {
		_, err := manager.EnsureRunning(context.Background(), first)
		firstDone <- err
	}()
	<-entered
	waitCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := manager.EnsureRunning(waitCtx, second); !IsCode(err, CodeTimeout) {
		t.Fatalf("busy wait error = %v", err)
	}
	close(gate)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	manager.locksMu.Lock()
	defer manager.locksMu.Unlock()
	if len(manager.locks) != 0 {
		t.Fatalf("completed service retained %d keyed locks", len(manager.locks))
	}
}

func TestGlobalTransactionAdmissionIsBounded(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	backend := &fakeBackend{startChanged: true, health: healthy(), startGate: gate, startEntered: entered}
	config := testConfig()
	config.MaxTransactions = 1
	config.StartTimeout = time.Second
	manager, _ := NewManager(backend, confirmer, config)
	firstTarget := targetFor(PlatformLinux, ServiceSSH)
	secondTarget := targetFor(PlatformWindows, ServiceSSH)
	secondTarget.Device[1] = 2
	first := confirmedRequest(t, confirmer, firstTarget)
	second := confirmedRequest(t, confirmer, secondTarget)
	firstDone := make(chan error, 1)
	go func() {
		_, err := manager.EnsureRunning(context.Background(), first)
		firstDone <- err
	}()
	<-entered
	if _, err := manager.EnsureRunning(context.Background(), second); !IsCode(err, CodeTransactionCapacity) {
		t.Fatalf("admission error = %v", err)
	}
	close(gate)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	// Admission happens before consumption, so a capacity rejection does not
	// burn the target-local confirmation.
	if _, err := manager.EnsureRunning(context.Background(), second); err != nil {
		t.Fatalf("confirmation was consumed while awaiting admission: %v", err)
	}
}

func TestFullAdmissionDoesNotQueueBackgroundRequests(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	backend := &fakeBackend{startChanged: true, health: healthy(), startGate: gate, startEntered: entered}
	config := testConfig()
	config.MaxTransactions = 1
	config.StartTimeout = time.Second
	manager, _ := NewManager(backend, confirmer, config)
	target := targetFor(PlatformLinux, ServiceSSH)
	active := confirmedRequest(t, confirmer, target)
	activeDone := make(chan error, 1)
	go func() {
		_, err := manager.EnsureRunning(context.Background(), active)
		activeDone <- err
	}()
	<-entered

	const requests = 1000
	results := make(chan error, requests)
	var waiters sync.WaitGroup
	waiters.Add(requests)
	for index := range requests {
		go func(index int) {
			defer waiters.Done()
			hostileTarget := target
			hostileTarget.Device[1] = byte(index + 1)
			_, err := manager.EnsureRunning(context.Background(), Request{
				Target:       hostileTarget,
				Operation:    OperationEnsureRunning,
				Confirmation: ConfirmationToken{byte(index + 1)},
			})
			results <- err
		}(index)
	}
	allReturned := make(chan struct{})
	go func() {
		waiters.Wait()
		close(allReturned)
	}()
	select {
	case <-allReturned:
	case <-time.After(time.Second):
		t.Fatal("Background requests queued behind full admission")
	}
	close(results)
	for err := range results {
		if !IsCode(err, CodeTransactionCapacity) {
			t.Fatalf("overload error = %v", err)
		}
	}
	manager.locksMu.Lock()
	if len(manager.locks) != 1 {
		t.Fatalf("overload grew keyed locks to %d, want active lock only", len(manager.locks))
	}
	manager.locksMu.Unlock()

	// A valid token rejected at admission must remain usable.
	otherTarget := targetFor(PlatformWindows, ServiceSSH)
	otherTarget.Device[1] = 3
	preserved := confirmedRequest(t, confirmer, otherTarget)
	if _, err := manager.EnsureRunning(context.Background(), preserved); !IsCode(err, CodeTransactionCapacity) {
		t.Fatalf("valid overload error = %v", err)
	}
	close(gate)
	if err := <-activeDone; err != nil {
		t.Fatal(err)
	}
	if _, err := manager.EnsureRunning(context.Background(), preserved); err != nil {
		t.Fatalf("admission consumed valid confirmation: %v", err)
	}
	manager.locksMu.Lock()
	defer manager.locksMu.Unlock()
	if len(manager.locks) != 0 {
		t.Fatalf("completed requests retained %d keyed locks", len(manager.locks))
	}
}

func TestCanceledBeforeCaptureConsumesNothingUnsafe(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	backend := &fakeBackend{}
	manager, _ := NewManager(backend, confirmer, testConfig())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := manager.EnsureRunning(ctx, confirmedRequest(t, confirmer, targetFor(PlatformLinux, ServiceSSH)))
	if !IsCode(err, CodeCanceled) || backend.captureCalls != 0 {
		t.Fatalf("err=%v captures=%d", err, backend.captureCalls)
	}
}

func TestUnsupportedTargetsAndOperations(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	manager, _ := NewManager(&fakeBackend{}, confirmer, testConfig())
	for _, target := range []Target{
		targetFor(PlatformAndroid, ServiceSSH),
		targetFor(PlatformIOS, ServiceVNC),
		targetFor(PlatformLinux, ServiceRDP),
		targetFor(PlatformLinux, ServiceVNC),
		targetFor(PlatformMacOS, ServiceRDP),
		targetFor(PlatformWindows, ServiceVNC),
		targetFor(PlatformUnknown, ServiceSSH),
	} {
		request := Request{Target: target, Operation: OperationEnsureRunning, Confirmation: ConfirmationToken{1}}
		if _, err := manager.EnsureRunning(context.Background(), request); !IsCode(err, CodeUnsupportedTarget) {
			t.Fatalf("target=%+v err=%v", target, err)
		}
	}
	request := confirmedRequest(t, confirmer, targetFor(PlatformWindows, ServiceSSH))
	request.Operation = Operation(255)
	if _, err := manager.EnsureRunning(context.Background(), request); !IsCode(err, CodeInvalidRequest) {
		t.Fatalf("operation error = %v", err)
	}
}

func TestNilDependenciesAndNilContexts(t *testing.T) {
	if _, err := NewConfirmer(nil, Config{}); !IsCode(err, CodeInvalidRequest) {
		t.Fatalf("confirmer error = %v", err)
	}
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	if _, err := NewManager(nil, confirmer, Config{}); !IsCode(err, CodeInvalidRequest) {
		t.Fatalf("manager backend error = %v", err)
	}
	if _, err := NewManager(&fakeBackend{}, nil, Config{}); !IsCode(err, CodeInvalidRequest) {
		t.Fatalf("manager confirmer error = %v", err)
	}
	manager, _ := NewManager(&fakeBackend{}, confirmer, Config{})
	//lint:ignore SA1012 This deliberately verifies the public API rejects a nil context.
	if _, err := manager.Detect(nil, targetFor(PlatformLinux, ServiceSSH)); !IsCode(err, CodeInvalidRequest) {
		t.Fatalf("detect error = %v", err)
	}
	//lint:ignore SA1012 This deliberately verifies the mutation API rejects a nil context.
	if _, err := manager.EnsureRunning(nil, Request{}); !IsCode(err, CodeInvalidRequest) {
		t.Fatalf("ensure error = %v", err)
	}
}

func TestPublicRequestAndReceiptHaveNoFreeFormOrCredentialFields(t *testing.T) {
	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		switch typ.Kind() {
		case reflect.String, reflect.Slice, reflect.Map, reflect.Interface, reflect.Pointer:
			t.Fatalf("request contains hostile/free-form type %v", typ)
		case reflect.Struct:
			for index := range typ.NumField() {
				field := typ.Field(index)
				switch field.Name {
				case "Command", "Args", "Username", "Password", "Credential", "Path":
					t.Fatalf("request contains forbidden field %q", field.Name)
				}
				walk(field.Type)
			}
		case reflect.Array:
			walk(typ.Elem())
		}
	}
	walk(reflect.TypeOf(Request{}))
	walk(reflect.TypeOf(StartPermit{}))
	walk(reflect.TypeOf(ChangeReceipt{}))
}

func TestDetectDoesNotClaimTCPAloneIsHealthy(t *testing.T) {
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	backend := &fakeBackend{health: Health{Running: true, Listening: true, Healthy: true}}
	manager, _ := NewManager(backend, confirmer, testConfig())
	target := targetFor(PlatformWindows, ServiceSSH)
	health, err := manager.Detect(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if validHealth(health) {
		t.Fatal("a listener without service identity was accepted")
	}
}

package remoteservice

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"time"
)

// ErrRollbackConflict is returned by a backend when authoritative current
// state no longer matches the receipt's post-start revision.
var ErrRollbackConflict = errors.New("remote service rollback conflict")

// ErrOwnershipUnproven means a service may have changed but the backend could
// not prove this transaction owns the stopped-to-running transition.
var ErrOwnershipUnproven = errors.New("remote service transition ownership unproven")

// ErrManualCleanupRequired means a fixed start may have changed local service
// state, but no atomic stop authority exists. Callers must surface this state.
var ErrManualCleanupRequired = errors.New("remote service manual cleanup required")

// Backend is a closed, typed OS adapter. Implementations must map Target to a
// compile-time allowlist of service-manager operations. They must not derive
// commands, arguments, users, passwords, or paths from remote input. Every
// method must return promptly when its context is canceled. Rollback must
// freshly obtain the authoritative service revision, require
// receipt.AuthorizesRollback(target, before, revision), and return
// ErrRollbackConflict without changing state when that check fails.
type Backend interface {
	Capture(context.Context, Target) (ServiceState, error)
	Start(context.Context, Target, StartPermit) (ChangeReceipt, error)
	Detect(context.Context, Target) (Health, error)
	Rollback(context.Context, Target, ServiceState, ChangeReceipt) error
}

type serviceLock struct {
	held chan struct{}
	refs int
}

// Manager serializes and executes safe service-start transactions.
type Manager struct {
	backend   Backend
	confirmer *Confirmer
	config    Config
	random    io.Reader
	admission chan struct{}

	locksMu sync.Mutex
	locks   map[Target]*serviceLock
}

// NewManager creates a transaction manager.
func NewManager(backend Backend, confirmer *Confirmer, config Config) (*Manager, error) {
	if backend == nil || confirmer == nil {
		return nil, &Error{Code: CodeInvalidRequest}
	}
	config = config.normalized()
	return &Manager{
		backend:   backend,
		confirmer: confirmer,
		config:    config,
		locks:     make(map[Target]*serviceLock),
		random:    rand.Reader,
		admission: make(chan struct{}, config.MaxTransactions),
	}, nil
}

// Detect returns target-local, service-aware health without changing service
// state. It does not consume a confirmation.
func (m *Manager) Detect(ctx context.Context, target Target) (Health, error) {
	if ctx == nil {
		return Health{}, &Error{Code: CodeInvalidRequest}
	}
	if err := validateTarget(target); err != nil {
		return Health{}, err
	}
	health, err := detectWithTimeout(ctx, m.config.VerifyTimeout, m.backend, target)
	if err != nil {
		return Health{}, &Error{Code: contextErrorCode(err, CodeVerifyFailed), Cause: err}
	}
	return health, nil
}

// EnsureRunning consumes local confirmation and starts a fixed service if it
// is stopped. Only changes made by this transaction are eligible for rollback.
func (m *Manager) EnsureRunning(ctx context.Context, request Request) (Result, error) {
	if ctx == nil {
		return Result{}, &Error{Code: CodeInvalidRequest}
	}
	if request.Operation != OperationEnsureRunning {
		return Result{}, &Error{Code: CodeInvalidRequest}
	}
	if err := validateTarget(request.Target); err != nil {
		return Result{}, err
	}
	if err := m.acquireAdmission(ctx); err != nil {
		return Result{}, err
	}
	defer m.releaseAdmission()
	if err := m.confirmer.consume(request.Target, request.Confirmation); err != nil {
		return Result{}, err
	}

	lock := m.referenceLock(request.Target)
	if err := waitForLock(ctx, lock); err != nil {
		m.unreferenceLock(request.Target, lock)
		return Result{}, &Error{Code: contextCode(ctx, CodeCanceled), Cause: err}
	}
	defer func() {
		<-lock.held
		m.unreferenceLock(request.Target, lock)
	}()

	preState, err := captureWithTimeout(ctx, m.config.CaptureTimeout, m.backend, request.Target)
	if err != nil {
		return Result{}, &Error{Code: contextErrorCode(err, CodeCaptureFailed), Cause: err}
	}
	if preState.Running {
		health, verifyErr := detectWithTimeout(ctx, m.config.VerifyTimeout, m.backend, request.Target)
		if verifyErr != nil {
			return Result{}, &Error{Code: contextErrorCode(verifyErr, CodeAlreadyRunningUnhealthy), Cause: verifyErr}
		}
		if !validHealth(health) {
			return Result{}, &Error{Code: CodeAlreadyRunningUnhealthy}
		}
		return Result{Code: OutcomeAlreadyRunning, Health: health}, nil
	}

	permit, permitErr := m.newStartPermit(request.Target, preState)
	if permitErr != nil {
		return Result{}, &Error{Code: CodeStartFailed, Cause: permitErr}
	}
	receipt, startErr := startWithTimeout(ctx, m.config.StartTimeout, m.backend, request.Target, permit)
	if receipt.Changed() && !permit.accepts(receipt) {
		return Result{}, &Error{Code: CodeStartFailed, Cause: errors.New("backend returned invalid change receipt")}
	}
	if startErr != nil {
		if receipt.Changed() && !receipt.RollbackAuthorized() {
			return manualCleanupResult(
				contextErrorCode(startErr, CodeStartFailed),
				startErr,
			)
		}
		return m.failAndMaybeRollback(ctx, request.Target, preState, receipt,
			contextErrorCode(startErr, CodeStartFailed), startErr)
	}
	if !receipt.Changed() {
		return Result{}, &Error{Code: CodeStartFailed, Cause: errors.New("backend reported no start")}
	}

	health, verifyErr := detectWithTimeout(ctx, m.config.VerifyTimeout, m.backend, request.Target)
	if verifyErr != nil {
		return m.failAndMaybeRollback(ctx, request.Target, preState, receipt,
			contextErrorCode(verifyErr, CodeVerifyFailed), verifyErr)
	}
	if !validHealth(health) {
		return m.failAndMaybeRollback(ctx, request.Target, preState, receipt,
			CodeVerifyFailed, errors.New("service verification was incomplete"))
	}
	return Result{
		Code:              OutcomeStarted,
		Health:            health,
		RollbackAuthority: receipt.RollbackAuthorized(),
	}, nil
}

func (m *Manager) failAndMaybeRollback(
	parent context.Context,
	target Target,
	preState ServiceState,
	receipt ChangeReceipt,
	code ErrorCode,
	cause error,
) (Result, error) {
	if preState.Running || !receipt.Changed() {
		return Result{}, &Error{Code: code, Cause: cause}
	}
	if !receipt.RollbackAuthorized() {
		return manualCleanupResult(code, cause)
	}
	// Rollback has its own finite budget and is deliberately detached from a
	// canceled request so a change cannot be left behind by client disconnect.
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), m.config.RollbackTimeout)
	defer cancel()
	if err := rollbackWithContext(rollbackCtx, m.backend, target, preState, receipt); err != nil {
		rollbackCode := contextErrorCode(err, CodeRollbackFailed)
		if errors.Is(err, ErrRollbackConflict) {
			rollbackCode = CodeRollbackConflict
		}
		return Result{Code: OutcomeRollbackFailed, Rollback: true}, &Error{
			Code:          code,
			Cause:         cause,
			RollbackCode:  rollbackCode,
			RollbackCause: err,
		}
	}
	return Result{Code: OutcomeRolledBack, Rollback: true}, &Error{Code: code, Cause: cause}
}

func manualCleanupResult(code ErrorCode, cause error) (Result, error) {
	return Result{
			Code:             OutcomeManualCleanup,
			MayRemainRunning: true,
		}, &Error{
			Code:          code,
			Cause:         cause,
			RollbackCode:  CodeManualCleanupRequired,
			RollbackCause: ErrManualCleanupRequired,
		}
}

func (m *Manager) acquireAdmission(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return &Error{Code: contextCode(ctx, CodeCanceled), Cause: err}
	}
	select {
	case m.admission <- struct{}{}:
		return nil
	default:
		return &Error{Code: CodeTransactionCapacity}
	}
}

func (m *Manager) releaseAdmission() {
	<-m.admission
}

func (m *Manager) referenceLock(target Target) *serviceLock {
	m.locksMu.Lock()
	defer m.locksMu.Unlock()
	lock := m.locks[target]
	if lock == nil {
		lock = &serviceLock{held: make(chan struct{}, 1)}
		m.locks[target] = lock
	}
	lock.refs++
	return lock
}

func (m *Manager) unreferenceLock(target Target, lock *serviceLock) {
	m.locksMu.Lock()
	defer m.locksMu.Unlock()
	lock.refs--
	if lock.refs == 0 {
		delete(m.locks, target)
	}
}

func waitForLock(ctx context.Context, lock *serviceLock) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case lock.held <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) newStartPermit(target Target, before ServiceState) (StartPermit, error) {
	var nonce [32]byte
	if _, err := io.ReadFull(m.random, nonce[:]); err != nil {
		return StartPermit{}, err
	}
	if nonce == ([32]byte{}) {
		return StartPermit{}, errors.New("empty start permit")
	}
	return StartPermit{nonce: nonce, target: target, before: before}, nil
}

func (p StartPermit) accepts(receipt ChangeReceipt) bool {
	return receipt.nonce == p.nonce &&
		receipt.target == p.target &&
		receipt.before == p.before &&
		(receipt.after != (ServiceRevision{}) || receipt.uncertain)
}

func captureWithTimeout(ctx context.Context, timeoutDuration time.Duration, backend Backend, target Target) (ServiceState, error) {
	callCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()
	state, err := backend.Capture(callCtx, target)
	if contextErr := callCtx.Err(); contextErr != nil {
		return state, contextErr
	}
	return state, err
}

func startWithTimeout(ctx context.Context, timeoutDuration time.Duration, backend Backend, target Target, permit StartPermit) (ChangeReceipt, error) {
	callCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()
	receipt, err := backend.Start(callCtx, target, permit)
	if contextErr := callCtx.Err(); contextErr != nil {
		return receipt, contextErr
	}
	return receipt, err
}

func detectWithTimeout(ctx context.Context, timeoutDuration time.Duration, backend Backend, target Target) (Health, error) {
	callCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()
	health, err := backend.Detect(callCtx, target)
	if contextErr := callCtx.Err(); contextErr != nil {
		return health, contextErr
	}
	return health, err
}

func rollbackWithContext(ctx context.Context, backend Backend, target Target, before ServiceState, receipt ChangeReceipt) error {
	err := backend.Rollback(ctx, target, before, receipt)
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}

func validHealth(health Health) bool {
	return health.Running && health.Listening && health.Healthy && health.IdentityVerified
}

func validateTarget(target Target) error {
	if target.Device == (DeviceID{}) {
		return &Error{Code: CodeInvalidRequest}
	}
	switch target.Platform {
	case PlatformLinux:
		if target.Service != ServiceSSH {
			return &Error{Code: CodeUnsupportedTarget}
		}
	case PlatformMacOS:
		if target.Service != ServiceSSH {
			return &Error{Code: CodeUnsupportedTarget}
		}
	case PlatformWindows:
		if target.Service != ServiceSSH && target.Service != ServiceRDP {
			return &Error{Code: CodeUnsupportedTarget}
		}
	default:
		return &Error{Code: CodeUnsupportedTarget}
	}
	return nil
}

func contextCode(ctx context.Context, fallback ErrorCode) ErrorCode {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return CodeTimeout
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return CodeCanceled
	}
	return fallback
}

func contextErrorCode(err error, fallback ErrorCode) ErrorCode {
	if errors.Is(err, context.DeadlineExceeded) {
		return CodeTimeout
	}
	if errors.Is(err, context.Canceled) {
		return CodeCanceled
	}
	return fallback
}

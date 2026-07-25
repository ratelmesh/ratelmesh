// Package remoteservice implements the platform-neutral transaction used to
// start a remote-access service after explicit, target-local confirmation.
package remoteservice

import (
	"errors"
	"time"
)

// Platform is a closed identifier for a target operating system.
type Platform uint8

const (
	PlatformUnknown Platform = iota
	PlatformLinux
	PlatformMacOS
	PlatformWindows
	PlatformAndroid
	PlatformIOS
)

// ServiceKind is a closed identifier for a remotely accessible service.
type ServiceKind uint8

const (
	ServiceUnknown ServiceKind = iota
	ServiceSSH
	ServiceRDP
	ServiceVNC
)

// Operation is deliberately closed. Backends never receive a command line.
type Operation uint8

const (
	OperationUnknown Operation = iota
	OperationEnsureRunning
)

// DeviceID is the stable binary identity of the target device.
type DeviceID [32]byte

// Target identifies exactly one service on one target.
type Target struct {
	Device   DeviceID
	Platform Platform
	Service  ServiceKind
}

// ConfirmationToken is an opaque, target-local, single-use capability.
type ConfirmationToken [32]byte

// Request contains no commands, arguments, credentials, or free-form fields.
type Request struct {
	Target       Target
	Operation    Operation
	Confirmation ConfirmationToken
}

// ServiceState is captured by a platform backend before any change.
type ServiceState struct {
	Running bool
	Enabled bool
}

// Health is the service-native result of detection or verification.
//
// IdentityVerified means the backend identified the configured service using
// an OS service manager or a service-aware probe. A listening TCP port alone
// must never set IdentityVerified.
type Health struct {
	Running          bool
	Listening        bool
	Healthy          bool
	IdentityVerified bool
}

// ServiceRevision is a fixed-size backend-derived revision of service state.
// Backends should derive it from authoritative service-manager state, including
// enough generation data to distinguish an external stop/start cycle.
type ServiceRevision [32]byte

// StartPermit is minted inside Manager for one exact target and captured
// pre-state. Its fields are deliberately opaque; it is not remote input.
type StartPermit struct {
	nonce  [32]byte
	target Target
	before ServiceState
}

// ChangeReceipt proves that the backend used a Manager-minted permit for the
// exact stopped-to-running change. Its fields cannot be populated by callers.
type ChangeReceipt struct {
	nonce     [32]byte
	ownership [32]byte
	target    Target
	before    ServiceState
	after     ServiceRevision
	uncertain bool
}

// CommitOwned records the authoritative post-start revision and the opaque
// ownership proof issued by an atomic native service transition. Both must be
// nonzero; observing a state change alone is not ownership.
func (p StartPermit) CommitOwned(after ServiceRevision, ownership [32]byte) ChangeReceipt {
	if p.nonce == ([32]byte{}) || after == (ServiceRevision{}) || ownership == ([32]byte{}) {
		return ChangeReceipt{}
	}
	return ChangeReceipt{
		nonce:     p.nonce,
		ownership: ownership,
		target:    p.target,
		before:    p.before,
		after:     after,
	}
}

// CommitObserved records an authoritative post-state without claiming
// ownership of the transition. It can support a successful start, but never
// authorizes automatic stop rollback.
func (p StartPermit) CommitObserved(after ServiceRevision) ChangeReceipt {
	if p.nonce == ([32]byte{}) || after == (ServiceRevision{}) {
		return ChangeReceipt{}
	}
	return ChangeReceipt{
		nonce:  p.nonce,
		target: p.target,
		before: p.before,
		after:  after,
	}
}

// CommitUncertain records that a fixed mutation was attempted but its
// post-state could not be read. It requires manual cleanup and never
// authorizes automatic rollback.
func (p StartPermit) CommitUncertain() ChangeReceipt {
	if p.nonce == ([32]byte{}) {
		return ChangeReceipt{}
	}
	return ChangeReceipt{
		nonce:     p.nonce,
		target:    p.target,
		before:    p.before,
		uncertain: true,
	}
}

// Changed reports whether this is a non-empty receipt.
func (r ChangeReceipt) Changed() bool {
	return r.nonce != ([32]byte{}) &&
		(r.after != (ServiceRevision{}) || r.uncertain)
}

// RollbackAuthorized reports whether a native atomic transition granted
// conditional automatic rollback authority.
func (r ChangeReceipt) RollbackAuthorized() bool {
	return r.Changed() &&
		r.ownership != ([32]byte{}) &&
		r.after != (ServiceRevision{}) &&
		!r.uncertain
}

// PostRevision returns the service revision that conditional rollback must
// compare with authoritative current state.
func (r ChangeReceipt) PostRevision() ServiceRevision {
	return r.after
}

// AuthorizesRollback verifies the receipt's exact binding. A backend must call
// this with its freshly observed current revision before changing state.
func (r ChangeReceipt) AuthorizesRollback(target Target, before ServiceState, current ServiceRevision) bool {
	return r.RollbackAuthorized() &&
		r.target == target &&
		r.before == before &&
		r.after == current
}

func (r ChangeReceipt) ownershipToken() [32]byte {
	return r.ownership
}

// OutcomeCode is a stable machine-readable transaction outcome.
type OutcomeCode string

const (
	OutcomeStarted        OutcomeCode = "started"
	OutcomeAlreadyRunning OutcomeCode = "already_running"
	OutcomeRolledBack     OutcomeCode = "rolled_back"
	OutcomeRollbackFailed OutcomeCode = "rollback_failed"
	OutcomeManualCleanup  OutcomeCode = "partial_manual_cleanup_required"
)

// Result reports a completed transaction without exposing backend details.
type Result struct {
	Code              OutcomeCode
	Health            Health
	Rollback          bool
	RollbackAuthority bool
	MayRemainRunning  bool
}

// ErrorCode is a stable machine-readable failure code.
type ErrorCode string

const (
	CodeInvalidRequest          ErrorCode = "invalid_request"
	CodeUnsupportedTarget       ErrorCode = "unsupported_target"
	CodeConfirmationDenied      ErrorCode = "confirmation_denied"
	CodeConfirmationExpired     ErrorCode = "confirmation_expired"
	CodeConfirmationInvalid     ErrorCode = "confirmation_invalid"
	CodeConfirmationReplay      ErrorCode = "confirmation_replay"
	CodeConfirmationCapacity    ErrorCode = "confirmation_capacity"
	CodeTransactionCapacity     ErrorCode = "transaction_capacity"
	CodeCaptureFailed           ErrorCode = "capture_failed"
	CodeStartFailed             ErrorCode = "start_failed"
	CodeVerifyFailed            ErrorCode = "verify_failed"
	CodeAlreadyRunningUnhealthy ErrorCode = "already_running_unhealthy"
	CodeRollbackFailed          ErrorCode = "rollback_failed"
	CodeRollbackConflict        ErrorCode = "rollback_conflict"
	CodeManualCleanupRequired   ErrorCode = "manual_cleanup_required"
	CodeCanceled                ErrorCode = "canceled"
	CodeTimeout                 ErrorCode = "timeout"
)

// Error is a stable transaction error. Cause and RollbackCause are for local
// diagnostics; callers should expose only Code and RollbackCode remotely.
type Error struct {
	Code          ErrorCode
	Cause         error
	RollbackCode  ErrorCode
	RollbackCause error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.RollbackCode != "" {
		return string(e.Code) + " (rollback: " + string(e.RollbackCode) + ")"
	}
	return string(e.Code)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// IsCode reports whether err is a remoteservice error with code.
func IsCode(err error, code ErrorCode) bool {
	var serviceErr *Error
	return errors.As(err, &serviceErr) && serviceErr.Code == code
}

// Config bounds every external operation.
type Config struct {
	ConfirmationTTL     time.Duration
	ConfirmationTimeout time.Duration
	CaptureTimeout      time.Duration
	StartTimeout        time.Duration
	VerifyTimeout       time.Duration
	RollbackTimeout     time.Duration
	MaxConfirmations    int
	MaxTransactions     int
}

func (c Config) normalized() Config {
	if c.ConfirmationTTL <= 0 {
		c.ConfirmationTTL = 2 * time.Minute
	}
	if c.ConfirmationTTL > 5*time.Minute {
		c.ConfirmationTTL = 5 * time.Minute
	}
	if c.ConfirmationTimeout <= 0 {
		c.ConfirmationTimeout = 30 * time.Second
	}
	if c.ConfirmationTimeout > 2*time.Minute {
		c.ConfirmationTimeout = 2 * time.Minute
	}
	if c.CaptureTimeout <= 0 {
		c.CaptureTimeout = 5 * time.Second
	}
	if c.CaptureTimeout > 30*time.Second {
		c.CaptureTimeout = 30 * time.Second
	}
	if c.StartTimeout <= 0 {
		c.StartTimeout = 20 * time.Second
	}
	if c.StartTimeout > 2*time.Minute {
		c.StartTimeout = 2 * time.Minute
	}
	if c.VerifyTimeout <= 0 {
		c.VerifyTimeout = 10 * time.Second
	}
	if c.VerifyTimeout > 30*time.Second {
		c.VerifyTimeout = 30 * time.Second
	}
	if c.RollbackTimeout <= 0 {
		c.RollbackTimeout = 15 * time.Second
	}
	if c.RollbackTimeout > time.Minute {
		c.RollbackTimeout = time.Minute
	}
	if c.MaxConfirmations <= 0 {
		c.MaxConfirmations = 256
	}
	if c.MaxConfirmations > 4096 {
		c.MaxConfirmations = 4096
	}
	if c.MaxTransactions <= 0 {
		c.MaxTransactions = 64
	}
	if c.MaxTransactions > 1024 {
		c.MaxTransactions = 1024
	}
	return c
}

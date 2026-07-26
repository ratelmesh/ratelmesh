package remoteaccess

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	MaxPolicyPayloadSize = 4096
	MaxPolicyStoreSize   = 64 << 10
	MaxPolicyTenants     = 256
)

var (
	policySignatureDomain    = []byte("RatelMesh-Remote-Access-Policy-v1\x00")
	ErrInvalidPolicyState    = errors.New("invalid remote access policy state")
	ErrPolicyRollback        = errors.New("remote access policy rollback")
	ErrPolicyConflict        = errors.New("conflicting remote access policy state")
	ErrPolicyDisabled        = errors.New("remote access policy is disabled")
	ErrPolicyStoreCorrupt    = errors.New("remote access policy store is corrupt")
	ErrPolicyStoreMode       = errors.New("remote access policy store permissions are too broad")
	ErrPolicyLockUnavailable = errors.New("remote access policy store lock unavailable")
)

// PolicyState is authority-signed policy state. Enabled is covered by the
// signature, so an unsigned or stale netmap cannot re-enable access.
type PolicyState struct {
	TenantID string    `json:"tenantId"`
	Version  uint64    `json:"version"`
	Enabled  bool      `json:"enabled"`
	IssuedAt time.Time `json:"issuedAt"`
}

// SignedPolicyState uses a domain distinct from node credentials and grants.
type SignedPolicyState struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// VerifiedPolicyState includes the signed payload digest persisted at the
// monotonic floor. Equal-version state must retain this digest.
type VerifiedPolicyState struct {
	PolicyState
	Digest     string    `json:"digest"`
	ObservedAt time.Time `json:"observedAt,omitempty"`
}

// PolicyPayloadDigest identifies one exact signed policy payload. It does not
// verify the signature; callers use it only after signing locally or verifying
// with VerifyPolicyState.
func PolicyPayloadDigest(signed SignedPolicyState) (string, error) {
	if len(signed.Payload) == 0 || len(signed.Payload) > MaxPolicyPayloadSize {
		return "", ErrPayloadTooLarge
	}
	digest := sha256.Sum256(signed.Payload)
	return hex.EncodeToString(digest[:]), nil
}

func policySigningMessage(payload []byte) []byte {
	out := make([]byte, 0, len(policySignatureDomain)+len(payload))
	out = append(out, policySignatureDomain...)
	return append(out, payload...)
}

func SignPolicyState(state PolicyState, signer Signer) (SignedPolicyState, error) {
	if signer == nil {
		return SignedPolicyState{}, ErrNilPointer
	}
	if err := validatePolicyState(state); err != nil {
		return SignedPolicyState{}, err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return SignedPolicyState{}, err
	}
	signature, err := signer.Sign(policySigningMessage(payload))
	if err != nil {
		return SignedPolicyState{}, err
	}
	return SignedPolicyState{Payload: payload, Signature: signature}, nil
}

func validatePolicyState(state PolicyState) error {
	if state.TenantID == "" || len(state.TenantID) > 256 || containsControlChars(state.TenantID) ||
		state.Version == 0 || state.IssuedAt.IsZero() {
		return ErrInvalidPolicyState
	}
	return nil
}

// VerifyPolicyState authenticates and binds state to the expected tenant.
func VerifyPolicyState(signed SignedPolicyState, verifier Verifier, tenantID string, now time.Time) (VerifiedPolicyState, error) {
	if verifier == nil || tenantID == "" || now.IsZero() {
		return VerifiedPolicyState{}, ErrInvalidVerificationContext
	}
	if len(signed.Payload) == 0 || len(signed.Payload) > MaxPolicyPayloadSize {
		return VerifiedPolicyState{}, ErrPayloadTooLarge
	}
	if len(signed.Signature) == 0 || len(signed.Signature) > MaxSignatureSize {
		return VerifiedPolicyState{}, ErrInvalidSignature
	}
	if !verifier.Verify(policySigningMessage(signed.Payload), signed.Signature) {
		return VerifiedPolicyState{}, ErrInvalidSignature
	}
	var state PolicyState
	dec := json.NewDecoder(bytes.NewReader(signed.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&state); err != nil {
		return VerifiedPolicyState{}, ErrInvalidPolicyState
	}
	if err := ensureJSONEOF(dec); err != nil {
		return VerifiedPolicyState{}, ErrInvalidPolicyState
	}
	if err := validatePolicyState(state); err != nil {
		return VerifiedPolicyState{}, err
	}
	if state.TenantID != tenantID || state.IssuedAt.After(now.Add(5*time.Minute)) {
		return VerifiedPolicyState{}, ErrBindingMismatch
	}
	digest, err := PolicyPayloadDigest(signed)
	if err != nil {
		return VerifiedPolicyState{}, err
	}
	return VerifiedPolicyState{PolicyState: state, Digest: digest, ObservedAt: now.UTC()}, nil
}

func ensureJSONEOF(dec *json.Decoder) error {
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return ErrInvalidPolicyState
		}
		return err
	}
	return nil
}

// PolicyFloorStore atomically accepts monotonic signed policy state.
type PolicyFloorStore interface {
	Load(tenantID string) (VerifiedPolicyState, bool, error)
	Advance(state VerifiedPolicyState) error
}

func checkPolicyAdvance(current VerifiedPolicyState, ok bool, next VerifiedPolicyState) error {
	if err := validatePolicyState(next.PolicyState); err != nil || !isCanonicalPolicyDigest(next.Digest) {
		return ErrInvalidPolicyState
	}
	if !ok {
		return nil
	}
	if next.Version < current.Version {
		return ErrPolicyRollback
	}
	// A strictly newer authority-signed policy is the recovery boundary for a
	// device whose local clock jumped far into the future. Keeping the old
	// observation across versions would permanently deny every later grant.
	// Equal-version observations remain monotonic, so replaying the same signed
	// policy cannot move time backwards and revive an expired grant.
	if next.Version == current.Version && !current.ObservedAt.IsZero() &&
		(next.ObservedAt.IsZero() || next.ObservedAt.Before(current.ObservedAt)) {
		return ErrPolicyRollback
	}
	if next.Version == current.Version &&
		(next.Digest != current.Digest || next.Enabled != current.Enabled || !next.IssuedAt.Equal(current.IssuedAt)) {
		return ErrPolicyConflict
	}
	return nil
}

func samePolicyState(current, next VerifiedPolicyState) bool {
	return current.TenantID == next.TenantID &&
		current.Version == next.Version &&
		current.Digest == next.Digest &&
		current.Enabled == next.Enabled &&
		current.IssuedAt.Equal(next.IssuedAt) &&
		current.ObservedAt.Equal(next.ObservedAt)
}

// PolicyTimeFloor returns a wall time that never moves behind the last
// successfully persisted policy observation. It prevents a clock rollback
// across process restart from making an already-expired temporary grant appear
// valid again.
func PolicyTimeFloor(store PolicyFloorStore, tenantID string, now time.Time) (time.Time, error) {
	if store == nil || tenantID == "" || now.IsZero() {
		return time.Time{}, ErrInvalidVerificationContext
	}
	current, ok, err := store.Load(tenantID)
	if err != nil {
		return time.Time{}, err
	}
	now = now.UTC()
	if ok && current.ObservedAt.After(now) {
		return current.ObservedAt.UTC(), nil
	}
	return now, nil
}

// ObservePolicyAt records the actual local observation time for an initial or
// strictly newer signed policy. Verification may have used a persisted future
// floor to keep old grants expired; carrying that artificial time into a newer
// policy would prevent the signed recovery boundary from taking effect.
func ObservePolicyAt(next VerifiedPolicyState, current VerifiedPolicyState, exists bool, now time.Time) (VerifiedPolicyState, error) {
	if now.IsZero() {
		return VerifiedPolicyState{}, ErrInvalidVerificationContext
	}
	if !exists || next.Version > current.Version {
		next.ObservedAt = now.UTC()
	}
	return next, nil
}

func isCanonicalPolicyDigest(digest string) bool {
	if len(digest) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size {
		return false
	}
	return hex.EncodeToString(decoded) == digest
}

// MemoryPolicyFloorStore is race-safe and useful where persistence is supplied
// by the embedding platform.
type MemoryPolicyFloorStore struct {
	mu      sync.RWMutex
	records map[string]VerifiedPolicyState
}

func NewMemoryPolicyFloorStore() *MemoryPolicyFloorStore {
	return &MemoryPolicyFloorStore{records: make(map[string]VerifiedPolicyState)}
}

func (s *MemoryPolicyFloorStore) Load(tenantID string) (VerifiedPolicyState, bool, error) {
	if s == nil {
		return VerifiedPolicyState{}, false, ErrNilPointer
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.records[tenantID]
	return state, ok, nil
}

func (s *MemoryPolicyFloorStore) Advance(state VerifiedPolicyState) error {
	if s == nil {
		return ErrNilPointer
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[state.TenantID]
	if err := checkPolicyAdvance(current, ok, state); err != nil {
		return err
	}
	if !ok && len(s.records) >= MaxPolicyTenants {
		return ErrTooManyPolicyTenants
	}
	if ok && samePolicyState(current, state) {
		return nil
	}
	s.records[state.TenantID] = state
	return nil
}

var ErrTooManyPolicyTenants = errors.New("too many policy tenants")

type policyStoreDocument struct {
	Records map[string]VerifiedPolicyState `json:"records"`
}

// FilePolicyFloorStore persists signed policy floors using a same-directory
// fsync-and-rename commit. Files are private (0600); directories are 0700.
type FilePolicyFloorStore struct {
	mu                 sync.Mutex
	root               *os.Root
	name               string
	closed             bool
	afterReadForTest   func()
	beforeWriteForTest func()
}

// NewFilePolicyFloorStore confines all state access to an already-existing,
// private root directory and a single relative basename. It never creates or
// chmods the root, avoiding symlink-following mutations of external paths.
func NewFilePolicyFloorStore(rootDir, name string) (*FilePolicyFloorStore, error) {
	return newFilePolicyFloorStore(rootDir, name, nil)
}

func newFilePolicyFloorStore(rootDir, name string, afterInitialStat func()) (*FilePolicyFloorStore, error) {
	if rootDir == "" || !filepath.IsAbs(rootDir) || name == "" ||
		name == "." || name == ".." || filepath.Base(name) != name ||
		strings.ContainsAny(name, `/\`) {
		return nil, ErrInvalidID
	}
	rootInfo, err := os.Lstat(filepath.Clean(rootDir))
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 ||
		rootInfo.Mode().Perm()&0o077 != 0 {
		return nil, ErrPolicyStoreMode
	}
	if afterInitialStat != nil {
		afterInitialStat()
	}
	root, err := os.OpenRoot(filepath.Clean(rootDir))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPolicyStoreCorrupt, err)
	}
	openedInfo, err := root.Stat(".")
	if err != nil || !openedInfo.IsDir() || openedInfo.Mode().Perm()&0o077 != 0 ||
		!os.SameFile(rootInfo, openedInfo) {
		root.Close()
		return nil, ErrPolicyStoreMode
	}
	finalInfo, err := os.Lstat(filepath.Clean(rootDir))
	if err != nil || !finalInfo.IsDir() || finalInfo.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(openedInfo, finalInfo) {
		root.Close()
		return nil, ErrPolicyStoreMode
	}
	return &FilePolicyFloorStore{root: root, name: name}, nil
}

func (s *FilePolicyFloorStore) Close() error {
	if s == nil {
		return ErrNilPointer
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil || s.closed {
		return ErrNilPointer
	}
	s.closed = true
	return s.root.Close()
}

func (s *FilePolicyFloorStore) Load(tenantID string) (VerifiedPolicyState, bool, error) {
	if s == nil {
		return VerifiedPolicyState{}, false, ErrNilPointer
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.acquireLockLocked()
	if err != nil {
		return VerifiedPolicyState{}, false, err
	}
	defer s.releaseLockLocked(lock)
	doc, err := s.readLocked()
	if err != nil {
		return VerifiedPolicyState{}, false, err
	}
	state, ok := doc.Records[tenantID]
	return state, ok, nil
}

func (s *FilePolicyFloorStore) Advance(state VerifiedPolicyState) error {
	if s == nil {
		return ErrNilPointer
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.acquireLockLocked()
	if err != nil {
		return err
	}
	defer s.releaseLockLocked(lock)
	doc, err := s.readLocked()
	if err != nil {
		return err
	}
	current, ok := doc.Records[state.TenantID]
	if err := checkPolicyAdvance(current, ok, state); err != nil {
		return err
	}
	if s.afterReadForTest != nil {
		s.afterReadForTest()
	}
	if !ok && len(doc.Records) >= MaxPolicyTenants {
		return ErrTooManyPolicyTenants
	}
	if ok && samePolicyState(current, state) {
		return nil
	}
	doc.Records[state.TenantID] = state
	return s.writeLocked(doc)
}

func (s *FilePolicyFloorStore) acquireLockLocked() (*os.File, error) {
	if s.root == nil || s.closed {
		return nil, ErrPolicyLockUnavailable
	}
	lockName := "." + s.name + ".lock"
	if info, err := s.root.Lstat(lockName); err == nil && !info.Mode().IsRegular() {
		return nil, ErrPolicyLockUnavailable
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, ErrPolicyLockUnavailable
	}
	lock, err := s.root.OpenFile(lockName, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPolicyLockUnavailable, err)
	}
	if err := lock.Chmod(0o600); err != nil {
		lock.Close()
		return nil, fmt.Errorf("%w: %v", ErrPolicyLockUnavailable, err)
	}
	openedInfo, err := lock.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 {
		lock.Close()
		return nil, ErrPolicyLockUnavailable
	}
	currentInfo, err := s.root.Lstat(lockName)
	if err != nil || !currentInfo.Mode().IsRegular() || !os.SameFile(openedInfo, currentInfo) {
		lock.Close()
		return nil, ErrPolicyLockUnavailable
	}
	if err := lockPolicyFile(lock); err != nil {
		lock.Close()
		return nil, fmt.Errorf("%w: %v", ErrPolicyLockUnavailable, err)
	}
	return lock, nil
}

func (s *FilePolicyFloorStore) releaseLockLocked(lock *os.File) {
	if lock == nil {
		return
	}
	_ = unlockPolicyFile(lock)
	_ = lock.Close()
}

func (s *FilePolicyFloorStore) readLocked() (policyStoreDocument, error) {
	doc := policyStoreDocument{Records: make(map[string]VerifiedPolicyState)}
	info, err := s.root.Lstat(s.name)
	if errors.Is(err, os.ErrNotExist) {
		return doc, nil
	}
	if err != nil {
		return doc, fmt.Errorf("%w: %v", ErrPolicyStoreCorrupt, err)
	}
	if !info.Mode().IsRegular() {
		return doc, ErrPolicyStoreCorrupt
	}
	if info.Mode().Perm()&0o077 != 0 {
		return doc, ErrPolicyStoreMode
	}
	if info.Size() > MaxPolicyStoreSize {
		return doc, ErrPolicyStoreCorrupt
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return doc, ErrPolicyStoreCorrupt
	}
	f, err := s.root.Open(s.name)
	if err != nil {
		return doc, fmt.Errorf("%w: %v", ErrPolicyStoreCorrupt, err)
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() ||
		openedInfo.Mode().Perm()&0o077 != 0 || openedInfo.Size() > MaxPolicyStoreSize {
		return doc, ErrPolicyStoreCorrupt
	}
	currentInfo, err := s.root.Lstat(s.name)
	if err != nil || !currentInfo.Mode().IsRegular() || !os.SameFile(openedInfo, currentInfo) {
		return doc, ErrPolicyStoreCorrupt
	}
	dec := json.NewDecoder(io.LimitReader(f, MaxPolicyStoreSize+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil || doc.Records == nil {
		return policyStoreDocument{}, ErrPolicyStoreCorrupt
	}
	if err := ensureJSONEOF(dec); err != nil || len(doc.Records) > MaxPolicyTenants {
		return policyStoreDocument{}, ErrPolicyStoreCorrupt
	}
	for tenant, record := range doc.Records {
		if tenant != record.TenantID || checkPolicyAdvance(VerifiedPolicyState{}, false, record) != nil {
			return policyStoreDocument{}, ErrPolicyStoreCorrupt
		}
	}
	return doc, nil
}

func (s *FilePolicyFloorStore) writeLocked(doc policyStoreDocument) error {
	if s.beforeWriteForTest != nil {
		s.beforeWriteForTest()
	}
	rootInfo, err := s.root.Stat(".")
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm()&0o077 != 0 {
		return ErrPolicyStoreMode
	}
	payload, err := marshalPolicyDocument(doc)
	if err != nil {
		return err
	}
	tmpName, err := randomPolicyTempName(s.name)
	if err != nil {
		return err
	}
	tmp, err := s.root.OpenFile(tmpName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPolicyStoreCorrupt, err)
	}
	defer s.root.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("%w: %v", ErrPolicyStoreCorrupt, err)
	}
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		return fmt.Errorf("%w: %v", ErrPolicyStoreCorrupt, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("%w: %v", ErrPolicyStoreCorrupt, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("%w: %v", ErrPolicyStoreCorrupt, err)
	}
	if err := s.root.Rename(tmpName, s.name); err != nil {
		return fmt.Errorf("%w: %v", ErrPolicyStoreCorrupt, err)
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPolicyStoreCorrupt, err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("%w: %v", ErrPolicyStoreCorrupt, err)
	}
	return nil
}

func randomPolicyTempName(name string) (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("%w: %v", ErrPolicyStoreCorrupt, err)
	}
	return "." + name + ".tmp-" + hex.EncodeToString(nonce[:]), nil
}

func marshalPolicyDocument(doc policyStoreDocument) ([]byte, error) {
	if len(doc.Records) > MaxPolicyTenants {
		return nil, ErrTooManyPolicyTenants
	}
	// Materialize a stable insertion order before encoding; encoding/json also
	// sorts map keys, but this keeps that determinism explicit.
	keys := make([]string, 0, len(doc.Records))
	for key := range doc.Records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ordered := make(map[string]VerifiedPolicyState, len(keys))
	for _, key := range keys {
		ordered[key] = doc.Records[key]
	}
	payload, err := json.Marshal(policyStoreDocument{Records: ordered})
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxPolicyStoreSize {
		return nil, ErrPolicyStoreCorrupt
	}
	return payload, nil
}

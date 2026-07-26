package filetransfer

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Quota struct {
	MaxActiveTransfers        uint32
	MaxReservedBytes          int64
	MaxRetainedTransfers      uint32
	MaxRetainedPerTenant      uint32
	MaxRetainedPerDevice      uint32
	MaxActivePerTenant        uint32
	MaxReservedBytesPerTenant int64
	MaxActivePerDevice        uint32
	MaxReservedBytesPerDevice int64
}

func DefaultQuota() Quota {
	return Quota{
		MaxActiveTransfers: 16, MaxReservedBytes: 16 << 30, MaxRetainedTransfers: 64,
		MaxRetainedPerTenant: 32, MaxRetainedPerDevice: 8,
		MaxActivePerTenant: 8, MaxReservedBytesPerTenant: 8 << 30,
		MaxActivePerDevice: 4, MaxReservedBytesPerDevice: 4 << 30,
	}
}

type quotaUsage struct {
	active uint32
	bytes  int64
}

type reservationRecord struct {
	tenant string
	device string
	bytes  int64
}

type AdmissionManager struct {
	mu           sync.Mutex
	quota        Quota
	total        quotaUsage
	tenants      map[string]quotaUsage
	devices      map[string]quotaUsage
	reservations map[string]reservationRecord
	loadedRoots  map[string]os.FileInfo
	completed    map[string]retainedPrincipal
	refs         map[string]uint32
	owners       map[string]uint64
	nextOwner    uint64
}

type retainedPrincipal struct {
	tenant string
	device string
}

func NewAdmissionManager(quota Quota) (*AdmissionManager, error) {
	if quota == (Quota{}) {
		quota = DefaultQuota()
	}
	// The retained sub-limits were added after the aggregate quota. Derive safe
	// fair defaults for older callers which only set MaxRetainedTransfers, and
	// clamp copied DefaultQuota values when a test/operator lowers the global cap.
	if quota.MaxRetainedTransfers > 0 {
		fairTenant := quota.MaxRetainedTransfers / 2
		if fairTenant == 0 {
			fairTenant = 1
		}
		if quota.MaxRetainedPerTenant == 0 || quota.MaxRetainedPerTenant > quota.MaxRetainedTransfers {
			quota.MaxRetainedPerTenant = fairTenant
		}
		fairDevice := quota.MaxRetainedPerTenant / 4
		if fairDevice == 0 {
			fairDevice = 1
		}
		if quota.MaxRetainedPerDevice == 0 || quota.MaxRetainedPerDevice > quota.MaxRetainedPerTenant {
			quota.MaxRetainedPerDevice = fairDevice
		}
	}
	if quota.MaxActiveTransfers == 0 || quota.MaxReservedBytes <= 0 || quota.MaxRetainedTransfers == 0 ||
		quota.MaxRetainedPerTenant == 0 || quota.MaxRetainedPerDevice == 0 ||
		quota.MaxActivePerTenant == 0 || quota.MaxReservedBytesPerTenant <= 0 ||
		quota.MaxActivePerDevice == 0 || quota.MaxReservedBytesPerDevice <= 0 {
		return nil, fmt.Errorf("%w: invalid aggregate quota", ErrInvalidInput)
	}
	return &AdmissionManager{
		quota: quota, tenants: make(map[string]quotaUsage), devices: make(map[string]quotaUsage),
		reservations: make(map[string]reservationRecord), loadedRoots: make(map[string]os.FileInfo),
		completed: make(map[string]retainedPrincipal), refs: make(map[string]uint32), owners: make(map[string]uint64),
	}, nil
}

type admission struct {
	manager        *AdmissionManager
	tenant         string
	device         string
	reservationKey string
	completed      bool
	abortOwner     uint64
	activeOnce     sync.Once
}

func (m *AdmissionManager) begin(tenant, device string) (*admission, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: nil admission manager", ErrInvalidInput)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	tu, du := m.tenants[tenant], m.devices[tenant+"\x00"+device]
	if m.total.active >= m.quota.MaxActiveTransfers || tu.active >= m.quota.MaxActivePerTenant ||
		du.active >= m.quota.MaxActivePerDevice {
		return nil, fmt.Errorf("%w: active transfers", ErrLimitExceeded)
	}
	m.total.active++
	tu.active++
	du.active++
	m.tenants[tenant], m.devices[tenant+"\x00"+device] = tu, du
	return &admission{manager: m, tenant: tenant, device: device}, nil
}

func (a *admission) claimReservation(key string, bytes int64) error {
	if a == nil || a.manager == nil || key == "" || bytes < 0 {
		return fmt.Errorf("%w: reserved bytes", ErrInvalidInput)
	}
	m := a.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.completed[key]; ok {
		a.reservationKey, a.completed = key, true
		m.refs[key]++
		return nil
	}
	if existing, ok := m.reservations[key]; ok {
		if existing.tenant != a.tenant || existing.device != a.device || existing.bytes != bytes {
			return fmt.Errorf("%w: conflicting persisted reservation", ErrAuthentication)
		}
		a.reservationKey = key
		a.abortOwner = m.owners[key]
		m.refs[key]++
		return nil
	}
	if !m.canRetainLocked(a.tenant, a.device) {
		return fmt.Errorf("%w: retained transfers", ErrLimitExceeded)
	}
	if err := m.addReservedLocked(a.tenant, a.device, bytes); err != nil {
		return err
	}
	m.reservations[key] = reservationRecord{tenant: a.tenant, device: a.device, bytes: bytes}
	m.nextOwner++
	if m.nextOwner == 0 {
		m.nextOwner++
	}
	m.owners[key] = m.nextOwner
	m.refs[key]++
	a.reservationKey, a.abortOwner = key, m.nextOwner
	return nil
}

func (m *AdmissionManager) canRetainLocked(tenant, device string) bool {
	if uint32(len(m.reservations)+len(m.completed)) >= m.quota.MaxRetainedTransfers {
		return false
	}
	var tenantCount, deviceCount uint32
	for _, rec := range m.reservations {
		if rec.tenant == tenant {
			tenantCount++
			if rec.device == device {
				deviceCount++
			}
		}
	}
	for _, principal := range m.completed {
		if principal.tenant == tenant {
			tenantCount++
			if principal.device == device {
				deviceCount++
			}
		}
	}
	return tenantCount < m.quota.MaxRetainedPerTenant &&
		deviceCount < m.quota.MaxRetainedPerDevice
}

func (m *AdmissionManager) addReservedLocked(tenant, device string, bytes int64) error {
	tu, du := m.tenants[tenant], m.devices[tenant+"\x00"+device]
	if exceeds(m.total.bytes, bytes, m.quota.MaxReservedBytes) ||
		exceeds(tu.bytes, bytes, m.quota.MaxReservedBytesPerTenant) ||
		exceeds(du.bytes, bytes, m.quota.MaxReservedBytesPerDevice) {
		return fmt.Errorf("%w: reserved bytes", ErrLimitExceeded)
	}
	m.total.bytes += bytes
	tu.bytes += bytes
	du.bytes += bytes
	m.tenants[tenant], m.devices[tenant+"\x00"+device] = tu, du
	return nil
}

func exceeds(current, add, maximum int64) bool {
	return current < 0 || add < 0 || maximum < 0 || current > maximum || add > maximum-current
}

func (a *admission) closeActive() {
	if a == nil || a.manager == nil {
		return
	}
	a.activeOnce.Do(func() {
		m := a.manager
		m.mu.Lock()
		defer m.mu.Unlock()
		key := a.tenant + "\x00" + a.device
		tu, du := m.tenants[a.tenant], m.devices[key]
		m.total.active--
		tu.active--
		du.active--
		m.storeUsageLocked(a.tenant, key, tu, du)
		if a.reservationKey != "" && m.refs[a.reservationKey] > 0 {
			m.refs[a.reservationKey]--
			if m.refs[a.reservationKey] == 0 {
				delete(m.refs, a.reservationKey)
			}
		}
	})
}

func (a *admission) abortNewReservation() {
	if a == nil || a.manager == nil || a.reservationKey == "" || a.abortOwner == 0 {
		return
	}
	m := a.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.refs[a.reservationKey] != 0 || m.owners[a.reservationKey] != a.abortOwner {
		return
	}
	if rec, ok := m.reservations[a.reservationKey]; ok {
		m.dropReservationLocked(a.reservationKey, rec)
	}
}

func (a *admission) markReservationPersistent() {
	if a == nil || a.manager == nil || a.reservationKey == "" {
		return
	}
	a.manager.mu.Lock()
	if a.manager.owners[a.reservationKey] == a.abortOwner {
		delete(a.manager.owners, a.reservationKey)
	}
	a.abortOwner = 0
	a.manager.mu.Unlock()
}

func (a *admission) releaseReservation() {
	if a == nil || a.manager == nil || a.reservationKey == "" {
		return
	}
	m := a.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.reservations[a.reservationKey]
	if !ok {
		return
	}
	m.dropReservationLocked(a.reservationKey, rec)
}

func (a *admission) markCompleted() {
	if a == nil || a.manager == nil || a.reservationKey == "" {
		return
	}
	m := a.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if rec, ok := m.reservations[a.reservationKey]; ok {
		m.dropReservationLocked(a.reservationKey, rec)
	}
	m.completed[a.reservationKey] = retainedPrincipal{tenant: a.tenant, device: a.device}
}

func (m *AdmissionManager) dropReservation(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.refs[key] > 0 {
		return
	}
	delete(m.completed, key)
	rec, ok := m.reservations[key]
	if !ok {
		return
	}
	m.dropReservationLocked(key, rec)
}

func (m *AdmissionManager) storeUsageLocked(tenant, deviceKey string, tu, du quotaUsage) {
	if tu == (quotaUsage{}) {
		delete(m.tenants, tenant)
	} else {
		m.tenants[tenant] = tu
	}
	if du == (quotaUsage{}) {
		delete(m.devices, deviceKey)
	} else {
		m.devices[deviceKey] = du
	}
}

func reservationKey(stateDir, id string) (string, error) {
	absolute, err := filepath.Abs(stateDir)
	if err != nil {
		return "", fmt.Errorf("resolve transfer state root: %w", err)
	}
	return filepath.Clean(absolute) + "\x00" + id, nil
}

func (m *AdmissionManager) loadPersistent(root *os.Root, stateDir string) error {
	absolute, err := filepath.Abs(stateDir)
	if err != nil {
		return err
	}
	absolute = filepath.Clean(absolute)
	rootInfo, err := root.Stat(".")
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for path, knownInfo := range m.loadedRoots {
		current, statErr := os.Lstat(path)
		if statErr != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(knownInfo, current) {
			m.dropRootLocked(path, nil)
			delete(m.loadedRoots, path)
		}
	}
	for path := range m.loadedRoots {
		if !m.rootHasStateLocked(path) {
			delete(m.loadedRoots, path)
		}
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := dir.ReadDir(maxGCScannedEntries + 1)
	closeErr := dir.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	if len(entries) > maxGCScannedEntries {
		return fmt.Errorf("%w: too many state-root entries", ErrLimitExceeded)
	}
	observed := make(map[string]reservationRecord)
	observedCompleted := make(map[string]retainedPrincipal)
	for _, entry := range entries {
		id := entry.Name()
		if len(id) != transferIDSize*2 {
			continue
		}
		if _, err := hex.DecodeString(id); err != nil {
			continue
		}
		child, err := openVerifiedChild(root, id)
		if err != nil {
			continue
		}
		key := absolute + "\x00" + id
		if info, consumedErr := child.Lstat("consumed.state"); consumedErr == nil && info.Mode().IsRegular() {
			principal := retainedPrincipal{}
			if data, readErr := readBoundedRootFile(child, "reservation.state", 512); readErr == nil {
				if rec, parseErr := decodeReservation(data); parseErr == nil {
					principal = retainedPrincipal{tenant: rec.tenant, device: rec.device}
				}
			}
			observedCompleted[key] = principal
			_ = child.Close()
			continue
		}
		data, readErr := readBoundedRootFile(child, "reservation.state", 512)
		rec, parseErr := decodeReservation(data)
		if readErr != nil || parseErr != nil {
			rec = reservationRecord{tenant: "", device: "", bytes: DefaultLimits().MaxFileSize}
			if info, statErr := child.Lstat("content.part"); statErr == nil && info.Mode().IsRegular() &&
				info.Size() > rec.bytes {
				rec.bytes = info.Size()
			}
		}
		_ = child.Close()
		observed[key] = rec
	}
	m.dropRootLocked(absolute, func(key string) bool {
		_, reserved := observed[key]
		_, completed := observedCompleted[key]
		return reserved || completed
	})
	for key, principal := range observedCompleted {
		if existing, ok := m.completed[key]; ok {
			if existing == (retainedPrincipal{}) && principal != (retainedPrincipal{}) {
				m.completed[key] = principal
			}
			continue
		}
		if principal != (retainedPrincipal{}) && !m.canRetainLocked(principal.tenant, principal.device) {
			return fmt.Errorf("%w: retained transfers", ErrLimitExceeded)
		}
		if principal == (retainedPrincipal{}) &&
			uint32(len(m.reservations)+len(m.completed)) >= m.quota.MaxRetainedTransfers {
			return fmt.Errorf("%w: retained transfers", ErrLimitExceeded)
		}
		if old, ok := m.reservations[key]; ok && m.refs[key] == 0 {
			m.dropReservationLocked(key, old)
		}
		m.completed[key] = principal
	}
	for key, rec := range observed {
		if existing, ok := m.reservations[key]; ok {
			if existing == rec || m.refs[key] > 0 {
				if existing == rec {
					delete(m.owners, key)
				}
				continue
			}
			m.dropReservationLocked(key, existing)
		}
		if _, ok := m.completed[key]; ok {
			if m.refs[key] > 0 {
				continue
			}
			delete(m.completed, key)
		}
		if !m.canRetainLocked(rec.tenant, rec.device) {
			return fmt.Errorf("%w: retained transfers", ErrLimitExceeded)
		}
		if err := m.addReservedLocked(rec.tenant, rec.device, rec.bytes); err != nil {
			return err
		}
		m.reservations[key] = rec
	}
	m.loadedRoots[absolute] = rootInfo
	return nil
}

func (m *AdmissionManager) dropRootLocked(rootPath string, keep func(string) bool) {
	prefix := rootPath + "\x00"
	for key, rec := range m.reservations {
		if !strings.HasPrefix(key, prefix) || m.refs[key] > 0 || (keep != nil && keep(key)) {
			continue
		}
		m.dropReservationLocked(key, rec)
	}
	for key := range m.completed {
		if strings.HasPrefix(key, prefix) && m.refs[key] == 0 && (keep == nil || !keep(key)) {
			delete(m.completed, key)
		}
	}
}

func (m *AdmissionManager) rootHasStateLocked(rootPath string) bool {
	prefix := rootPath + "\x00"
	for key := range m.reservations {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	for key := range m.completed {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func (m *AdmissionManager) dropReservationLocked(key string, rec reservationRecord) {
	delete(m.reservations, key)
	delete(m.owners, key)
	deviceKey := rec.tenant + "\x00" + rec.device
	tu, du := m.tenants[rec.tenant], m.devices[deviceKey]
	m.total.bytes -= rec.bytes
	tu.bytes -= rec.bytes
	du.bytes -= rec.bytes
	m.storeUsageLocked(rec.tenant, deviceKey, tu, du)
}

var defaultAdmissionManager, _ = NewAdmissionManager(DefaultQuota())

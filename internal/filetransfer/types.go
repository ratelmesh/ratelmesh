package filetransfer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	ProtocolVersion  uint16 = 2
	DefaultChunkSize        = 1 << 20
)

var (
	ErrInvalidInput     = errors.New("file transfer: invalid input")
	ErrAuthentication   = errors.New("file transfer: authentication failed")
	ErrIntegrity        = errors.New("file transfer: integrity check failed")
	ErrConflictingChunk = errors.New("file transfer: conflicting chunk replay")
	ErrIncomplete       = errors.New("file transfer: incomplete")
	ErrAlreadyFinalized = errors.New("file transfer: already finalized")
	ErrAlreadyCompleted = errors.New("file transfer: transfer already completed")
	ErrLimitExceeded    = errors.New("file transfer: resource limit exceeded")
	ErrTransferBusy     = errors.New("file transfer: transfer already open")
	ErrDurability       = errors.New("file transfer: directory durability unavailable")
)

// Limits bounds every allocation influenced by an untrusted peer.
type Limits struct {
	MaxFileSize      int64
	MaxChunkSize     uint32
	MaxChunks        uint32
	MaxManifestBytes uint32
	MaxOfferBytes    uint32
	MaxResumeBytes   uint32
	MaxFilenameBytes uint16
}

func DefaultLimits() Limits {
	return Limits{
		MaxFileSize:      2 << 30,
		MaxChunkSize:     8 << 20,
		MaxChunks:        1 << 18,
		MaxManifestBytes: 9 << 20,
		MaxOfferBytes:    10 << 20,
		MaxResumeBytes:   1 << 20,
		MaxFilenameBytes: 255,
	}
}

func (l Limits) normalized() Limits {
	d := DefaultLimits()
	if l.MaxFileSize <= 0 {
		l.MaxFileSize = d.MaxFileSize
	}
	if l.MaxChunkSize == 0 {
		l.MaxChunkSize = d.MaxChunkSize
	}
	if l.MaxChunks == 0 {
		l.MaxChunks = d.MaxChunks
	}
	if l.MaxManifestBytes == 0 {
		l.MaxManifestBytes = d.MaxManifestBytes
	}
	if l.MaxOfferBytes == 0 {
		l.MaxOfferBytes = d.MaxOfferBytes
	}
	if l.MaxResumeBytes == 0 {
		l.MaxResumeBytes = d.MaxResumeBytes
	}
	if l.MaxFilenameBytes == 0 {
		l.MaxFilenameBytes = d.MaxFilenameBytes
	}
	return l
}

type identityMaterial struct {
	SigningPrivate ed25519.PrivateKey
	SigningPublic  ed25519.PublicKey
}

// Peer can only be produced by VerifyDeviceBinding. Its unexported key fields
// prevent an unverified Coordinator-supplied key from entering key agreement.
type Peer struct {
	signingPublic  [ed25519.PublicKeySize]byte
	exchangePublic [x25519KeySize]byte
	bindingDigest  [sha256.Size]byte
	tenantID       string
	deviceID       string
	keyVersion     uint64
	notBefore      time.Time
	notAfter       time.Time
}

// LocalDevice holds file-transfer-specific identity material. These exchange
// keys are distinct from WireGuard keys.
type LocalDevice struct {
	mu              sync.RWMutex
	closed          bool
	identity        identityMaterial
	exchangePrivate [x25519KeySize]byte
	peer            Peer
}

func (d *LocalDevice) snapshot() (identityMaterial, [x25519KeySize]byte, Peer, error) {
	if d == nil {
		return identityMaterial{}, [x25519KeySize]byte{}, Peer{}, fmt.Errorf("%w: nil local device", ErrInvalidInput)
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return identityMaterial{}, [x25519KeySize]byte{}, Peer{}, fmt.Errorf("%w: local device closed", ErrInvalidInput)
	}
	identity := identityMaterial{
		SigningPrivate: append(ed25519.PrivateKey(nil), d.identity.SigningPrivate...),
		SigningPublic:  append(ed25519.PublicKey(nil), d.identity.SigningPublic...),
	}
	return identity, d.exchangePrivate, d.peer, nil
}

// Manifest is immutable and cryptographically bound to every encrypted chunk.
type Manifest struct {
	Filename    string
	Size        int64
	ChunkSize   uint32
	ChunkHashes [][sha256.Size]byte
	ContentHash [sha256.Size]byte
}

func (m Manifest) ChunkCount() uint32 { return uint32(len(m.ChunkHashes)) }

func sanitizeFilename(name string, max uint16) (string, error) {
	if !utf8.ValidString(name) || name == "" || len(name) > int(max) || strings.IndexByte(name, 0) >= 0 {
		return "", fmt.Errorf("%w: unsafe filename", ErrInvalidInput)
	}
	if filepath.IsAbs(name) || filepath.Base(name) != name || name == "." || name == ".." ||
		strings.ContainsAny(name, `/\`) || strings.Contains(name, ":") {
		return "", fmt.Errorf("%w: unsafe filename", ErrInvalidInput)
	}
	trimmed := strings.TrimRight(name, " .")
	if trimmed == "" || trimmed != name {
		return "", fmt.Errorf("%w: unsafe filename", ErrInvalidInput)
	}
	upper := strings.ToUpper(strings.Split(name, ".")[0])
	switch upper {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return "", fmt.Errorf("%w: reserved filename", ErrInvalidInput)
	}
	return name, nil
}

func validateManifest(m Manifest, limits Limits) error {
	limits = limits.normalized()
	if _, err := sanitizeFilename(m.Filename, limits.MaxFilenameBytes); err != nil {
		return err
	}
	if m.Size < 0 || m.Size > limits.MaxFileSize {
		return fmt.Errorf("%w: file size", ErrLimitExceeded)
	}
	if m.ChunkSize == 0 || m.ChunkSize > limits.MaxChunkSize {
		return fmt.Errorf("%w: chunk size", ErrLimitExceeded)
	}
	want := uint64(0)
	if m.Size > 0 {
		want = (uint64(m.Size) + uint64(m.ChunkSize) - 1) / uint64(m.ChunkSize)
	}
	if want > uint64(limits.MaxChunks) || uint64(len(m.ChunkHashes)) != want {
		return fmt.Errorf("%w: chunk count", ErrLimitExceeded)
	}
	return nil
}

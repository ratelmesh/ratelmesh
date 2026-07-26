package filetransfer

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	chunkNonceContext         = []byte("RatelMesh-File-Transfer-Chunk-Nonce-v2\x00")
	chunkAADContext           = []byte("RatelMesh-File-Transfer-Chunk-AAD-v2\x00")
	manifestCommitmentContext = []byte("RatelMesh-File-Transfer-Manifest-Commitment-v2\x00")
)

type Sender struct {
	mu         sync.Mutex
	source     *os.File
	manifest   Manifest
	contentKey []byte
	offer      Offer
	closed     bool
}

// NewSender hashes an immutable snapshot of source and creates an offer for the
// intended recipient. It refuses to send a chunk if source later changes.
func NewSender(ctx context.Context, sourcePath string, sender *LocalDevice, recipient Peer, expiresAt time.Time, chunkSize uint32, limits Limits) (*Sender, error) {
	limits = limits.normalized()
	if chunkSize == 0 {
		chunkSize = DefaultChunkSize
	}
	if chunkSize > limits.MaxChunkSize {
		return nil, fmt.Errorf("%w: chunk size", ErrLimitExceeded)
	}
	f, err := os.Open(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("open source: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat source: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limits.MaxFileSize {
		return nil, fmt.Errorf("%w: source must be a bounded regular file", ErrInvalidInput)
	}
	name, err := sanitizeFilename(filepath.Base(sourcePath), limits.MaxFilenameBytes)
	if err != nil {
		return nil, err
	}
	m := Manifest{Filename: name, Size: info.Size(), ChunkSize: chunkSize}
	count := uint64(0)
	if info.Size() > 0 {
		count = (uint64(info.Size()) + uint64(chunkSize) - 1) / uint64(chunkSize)
	}
	if count > uint64(limits.MaxChunks) {
		return nil, fmt.Errorf("%w: chunk count", ErrLimitExceeded)
	}
	m.ChunkHashes = make([][sha256.Size]byte, int(count))
	whole := sha256.New()
	buf := make([]byte, int(chunkSize))
	for i := range m.ChunkHashes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		want := expectedPlaintextSize(m.Size, chunkSize, uint32(i), uint32(count))
		n, readErr := io.ReadFull(f, buf[:want])
		if readErr != nil {
			return nil, fmt.Errorf("%w: source changed while hashing: %v", ErrIntegrity, readErr)
		}
		_, _ = whole.Write(buf[:n])
		m.ChunkHashes[i] = sha256.Sum256(buf[:n])
	}
	var extra [1]byte
	if n, readErr := f.Read(extra[:]); n != 0 || readErr != io.EOF {
		return nil, fmt.Errorf("%w: source changed while hashing", ErrIntegrity)
	}
	copy(m.ContentHash[:], whole.Sum(nil))
	after, err := f.Stat()
	if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return nil, fmt.Errorf("%w: source changed while hashing", ErrIntegrity)
	}
	if err := validateManifest(m, limits); err != nil {
		return nil, err
	}
	raw := encodeManifest(m)
	if uint64(len(raw)) > uint64(limits.MaxManifestBytes) {
		return nil, fmt.Errorf("%w: manifest bytes", ErrLimitExceeded)
	}
	if uint64(bitmapLen(m.ChunkCount())+resumeTokenFixedSize) > uint64(limits.MaxResumeBytes) {
		return nil, fmt.Errorf("%w: resume state bytes", ErrLimitExceeded)
	}
	key := make([]byte, contentKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate content key: %w", err)
	}
	offer, err := makeOffer(ctx, m, key, sender, recipient, expiresAt, rand.Reader)
	if err != nil {
		zero(key)
		return nil, err
	}
	wire, err := offer.MarshalBinary()
	if err != nil {
		zero(key)
		return nil, err
	}
	if uint64(len(wire)) > uint64(limits.MaxOfferBytes) {
		zero(key)
		return nil, fmt.Errorf("%w: offer bytes", ErrLimitExceeded)
	}
	s := &Sender{
		source: f, manifest: m,
		contentKey: key, offer: offer,
	}
	ok = true
	return s, nil
}

func (s *Sender) Manifest() Manifest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneManifest(s.manifest)
}

func (s *Sender) Offer() Offer {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.offer
	o.Ciphertext = append([]byte(nil), o.Ciphertext...)
	return o
}

func (s *Sender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	zero(s.contentKey)
	s.contentKey = nil
	return s.source.Close()
}

type EncryptedChunk struct {
	Index         uint32
	PlaintextSize uint32
	Ciphertext    []byte
}

func (c EncryptedChunk) MarshalBinary() []byte {
	b := make([]byte, 0, 12+len(c.Ciphertext))
	b = appendU32(b, c.Index)
	b = appendU32(b, c.PlaintextSize)
	b = appendU32(b, uint32(len(c.Ciphertext)))
	b = append(b, c.Ciphertext...)
	return b
}

func ParseEncryptedChunk(b []byte, maxChunkSize uint32) (EncryptedChunk, error) {
	if maxChunkSize == 0 {
		maxChunkSize = DefaultLimits().MaxChunkSize
	}
	if uint64(len(b)) > uint64(maxChunkSize)+12+32 {
		return EncryptedChunk{}, fmt.Errorf("%w: encrypted chunk bytes", ErrLimitExceeded)
	}
	d := decoder{b: b}
	index, err := d.u32()
	if err != nil {
		return EncryptedChunk{}, fmt.Errorf("%w: chunk header", ErrInvalidInput)
	}
	size, err := d.u32()
	if err != nil || size > maxChunkSize {
		return EncryptedChunk{}, fmt.Errorf("%w: plaintext size", ErrLimitExceeded)
	}
	n, err := d.u32()
	if err != nil || n != size+16 || int(n) != len(b)-12 {
		return EncryptedChunk{}, fmt.Errorf("%w: ciphertext size", ErrInvalidInput)
	}
	c, err := d.take(int(n))
	if err != nil {
		return EncryptedChunk{}, fmt.Errorf("%w: truncated chunk", ErrInvalidInput)
	}
	return EncryptedChunk{Index: index, PlaintextSize: size, Ciphertext: append([]byte(nil), c...)}, nil
}

func (s *Sender) EncryptChunk(ctx context.Context, index uint32) (EncryptedChunk, error) {
	if err := ctx.Err(); err != nil {
		return EncryptedChunk{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return EncryptedChunk{}, os.ErrClosed
	}
	if uint64(index) >= uint64(len(s.manifest.ChunkHashes)) {
		return EncryptedChunk{}, fmt.Errorf("%w: chunk index", ErrInvalidInput)
	}
	n := expectedPlaintextSize(s.manifest.Size, s.manifest.ChunkSize, index, uint32(len(s.manifest.ChunkHashes)))
	buf := make([]byte, int(n))
	read, err := s.source.ReadAt(buf, int64(index)*int64(s.manifest.ChunkSize))
	if err != nil && err != io.EOF {
		return EncryptedChunk{}, fmt.Errorf("read source chunk: %w", err)
	}
	if read != len(buf) || sha256.Sum256(buf) != s.manifest.ChunkHashes[index] {
		zero(buf)
		return EncryptedChunk{}, fmt.Errorf("%w: source changed after manifest creation", ErrIntegrity)
	}
	defer zero(buf)
	aead, err := chunkAEAD(s.contentKey)
	if err != nil {
		return EncryptedChunk{}, err
	}
	nonce := chunkNonce(s.contentKey, s.offer.TransferID, index)
	aad := chunkAAD(s.offer.TransferID, s.offer.ManifestCommitment, index, n)
	ciphertext := aead.Seal(nil, nonce[:], buf, aad)
	return EncryptedChunk{Index: index, PlaintextSize: n, Ciphertext: ciphertext}, nil
}

func chunkAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create chunk cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create chunk AEAD: %w", err)
	}
	return aead, nil
}

func chunkNonce(key []byte, id [transferIDSize]byte, index uint32) [12]byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(chunkNonceContext)
	_, _ = m.Write(id[:])
	sum := m.Sum(nil)
	var out [12]byte
	// The prefix is transfer-specific; the encoded index makes every nonce
	// under this transfer's one-use content key unique by construction.
	copy(out[:8], sum[:8])
	binary.BigEndian.PutUint32(out[8:], index)
	zero(sum)
	return out
}

func chunkAAD(id [transferIDSize]byte, commitment [sha256.Size]byte, index, size uint32) []byte {
	b := make([]byte, 0, len(chunkAADContext)+2+transferIDSize+sha256.Size+8)
	b = append(b, chunkAADContext...)
	b = appendU16(b, ProtocolVersion)
	b = append(b, id[:]...)
	b = append(b, commitment[:]...)
	b = appendU32(b, index)
	b = appendU32(b, size)
	return b
}

func manifestCommitment(key []byte, id [transferIDSize]byte, manifest []byte) [sha256.Size]byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(manifestCommitmentContext)
	_, _ = m.Write(id[:])
	_, _ = m.Write(manifest)
	var out [sha256.Size]byte
	copy(out[:], m.Sum(nil))
	return out
}

func expectedPlaintextSize(size int64, chunkSize, index, count uint32) uint32 {
	if count == 0 {
		return 0
	}
	if index+1 < count {
		return chunkSize
	}
	return uint32(uint64(size) - uint64(index)*uint64(chunkSize))
}

func cloneManifest(m Manifest) Manifest {
	out := m
	out.ChunkHashes = append([][sha256.Size]byte(nil), m.ChunkHashes...)
	return out
}

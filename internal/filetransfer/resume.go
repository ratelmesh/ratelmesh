package filetransfer

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

var resumeContext = []byte("RatelMesh-File-Transfer-Resume-v2\x00")

const resumeTokenFixedSize = 4 + 2 + transferIDSize + sha256.Size*5 + 4 + sha256.Size

type ResumeToken struct {
	Version            uint16
	TransferID         [transferIDSize]byte
	ManifestCommitment [sha256.Size]byte
	SenderSigning      [32]byte
	RecipientSigning   [32]byte
	SenderBinding      [32]byte
	RecipientBinding   [32]byte
	Completed          []byte
	MAC                [sha256.Size]byte
}

func (t ResumeToken) authenticatedBytes() []byte {
	b := make([]byte, 0, len(resumeContext)+2+transferIDSize+32*5+4+len(t.Completed))
	b = append(b, resumeContext...)
	b = appendU16(b, t.Version)
	b = append(b, t.TransferID[:]...)
	b = append(b, t.ManifestCommitment[:]...)
	b = append(b, t.SenderSigning[:]...)
	b = append(b, t.RecipientSigning[:]...)
	b = append(b, t.SenderBinding[:]...)
	b = append(b, t.RecipientBinding[:]...)
	b = appendU32(b, uint32(len(t.Completed)))
	b = append(b, t.Completed...)
	return b
}

func (t ResumeToken) MarshalBinary() []byte {
	b := make([]byte, 0, 4+len(t.authenticatedBytes())-len(resumeContext)+sha256.Size)
	b = append(b, resumeMagic...)
	b = appendU16(b, t.Version)
	b = append(b, t.TransferID[:]...)
	b = append(b, t.ManifestCommitment[:]...)
	b = append(b, t.SenderSigning[:]...)
	b = append(b, t.RecipientSigning[:]...)
	b = append(b, t.SenderBinding[:]...)
	b = append(b, t.RecipientBinding[:]...)
	b = appendU32(b, uint32(len(t.Completed)))
	b = append(b, t.Completed...)
	b = append(b, t.MAC[:]...)
	return b
}

func ParseResumeToken(b []byte, limits Limits) (ResumeToken, error) {
	limits = limits.normalized()
	if uint64(len(b)) > uint64(limits.MaxResumeBytes) {
		return ResumeToken{}, fmt.Errorf("%w: resume bytes", ErrLimitExceeded)
	}
	if len(b) < resumeTokenFixedSize {
		return ResumeToken{}, fmt.Errorf("%w: truncated resume token", ErrInvalidInput)
	}
	d := decoder{b: b}
	magic, _ := d.take(4)
	if !bytes.Equal(magic, []byte(resumeMagic)) {
		return ResumeToken{}, fmt.Errorf("%w: resume magic", ErrInvalidInput)
	}
	var t ResumeToken
	var err error
	t.Version, err = d.u16()
	if err != nil || t.Version != ProtocolVersion {
		return ResumeToken{}, fmt.Errorf("%w: resume version", ErrInvalidInput)
	}
	for _, dst := range [][]byte{t.TransferID[:], t.ManifestCommitment[:], t.SenderSigning[:], t.RecipientSigning[:], t.SenderBinding[:], t.RecipientBinding[:]} {
		v, takeErr := d.take(len(dst))
		if takeErr != nil {
			return ResumeToken{}, fmt.Errorf("%w: truncated resume token", ErrInvalidInput)
		}
		copy(dst, v)
	}
	n, err := d.u32()
	if err != nil || n > limits.MaxResumeBytes || uint64(n)+resumeTokenFixedSize != uint64(len(b)) {
		return ResumeToken{}, fmt.Errorf("%w: resume bitmap size", ErrInvalidInput)
	}
	bits, err := d.take(int(n))
	if err != nil {
		return ResumeToken{}, fmt.Errorf("%w: truncated resume bitmap", ErrInvalidInput)
	}
	t.Completed = append([]byte(nil), bits...)
	mac, err := d.take(sha256.Size)
	if err != nil {
		return ResumeToken{}, fmt.Errorf("%w: truncated resume MAC", ErrInvalidInput)
	}
	copy(t.MAC[:], mac)
	return t, nil
}

func deriveResumeKey(contentKey []byte, id [transferIDSize]byte, commitment [sha256.Size]byte, sender, recipient, senderBinding, recipientBinding [32]byte) ([]byte, error) {
	saltInput := make([]byte, 0, transferIDSize+sha256.Size+128)
	saltInput = append(saltInput, id[:]...)
	saltInput = append(saltInput, commitment[:]...)
	saltInput = append(saltInput, sender[:]...)
	saltInput = append(saltInput, recipient[:]...)
	saltInput = append(saltInput, senderBinding[:]...)
	saltInput = append(saltInput, recipientBinding[:]...)
	salt := sha256.Sum256(saltInput)
	zero(saltInput)
	return hkdf.Key(sha256.New, contentKey, salt[:], string(resumeContext), sha256.Size)
}

func signResume(t *ResumeToken, key []byte) {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(t.authenticatedBytes())
	copy(t.MAC[:], m.Sum(nil))
}

func verifyResume(t ResumeToken, key []byte) bool {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(t.authenticatedBytes())
	return subtle.ConstantTimeCompare(t.MAC[:], m.Sum(nil)) == 1
}

func (s *Sender) MissingChunks(token ResumeToken) ([]uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("%w: sender closed", ErrInvalidInput)
	}
	if token.Version != ProtocolVersion || token.TransferID != s.offer.TransferID ||
		token.ManifestCommitment != s.offer.ManifestCommitment || token.SenderSigning != s.offer.SenderSigning ||
		token.RecipientSigning != s.offer.RecipientSigning || token.SenderBinding != s.offer.SenderBinding ||
		token.RecipientBinding != s.offer.RecipientBinding ||
		len(token.Completed) != bitmapLen(uint32(len(s.manifest.ChunkHashes))) {
		return nil, ErrAuthentication
	}
	key, err := deriveResumeKey(s.contentKey, s.offer.TransferID, s.offer.ManifestCommitment, s.offer.SenderSigning, s.offer.RecipientSigning, s.offer.SenderBinding, s.offer.RecipientBinding)
	if err != nil {
		return nil, err
	}
	defer zero(key)
	if !verifyResume(token, key) {
		return nil, ErrAuthentication
	}
	out := make([]uint32, 0)
	for i := uint32(0); i < uint32(len(s.manifest.ChunkHashes)); i++ {
		if !bitSet(token.Completed, i) {
			out = append(out, i)
		}
	}
	return out, nil
}

func bitmapLen(count uint32) int        { return int((uint64(count) + 7) / 8) }
func bitSet(bits []byte, i uint32) bool { return bits[i/8]&(1<<(i%8)) != 0 }
func setBit(bits []byte, i uint32)      { bits[i/8] |= 1 << (i % 8) }
func clearBit(bits []byte, i uint32)    { bits[i/8] &^= 1 << (i % 8) }

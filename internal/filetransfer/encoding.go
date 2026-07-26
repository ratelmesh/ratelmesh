package filetransfer

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	manifestMagic = "RMFM"
	offerMagic    = "RMFO"
	resumeMagic   = "RMFR"
)

func appendU16(dst []byte, n uint16) []byte { return binary.BigEndian.AppendUint16(dst, n) }
func appendU32(dst []byte, n uint32) []byte { return binary.BigEndian.AppendUint32(dst, n) }
func appendU64(dst []byte, n uint64) []byte { return binary.BigEndian.AppendUint64(dst, n) }

func encodeManifest(m Manifest) []byte {
	b := make([]byte, 0, 64+len(m.Filename)+len(m.ChunkHashes)*sha256.Size)
	b = append(b, manifestMagic...)
	b = appendU16(b, ProtocolVersion)
	b = appendU16(b, uint16(len(m.Filename)))
	b = append(b, m.Filename...)
	b = appendU64(b, uint64(m.Size))
	b = appendU32(b, m.ChunkSize)
	b = appendU32(b, uint32(len(m.ChunkHashes)))
	b = append(b, m.ContentHash[:]...)
	for _, h := range m.ChunkHashes {
		b = append(b, h[:]...)
	}
	return b
}

type decoder struct {
	b []byte
	i int
}

func (d *decoder) take(n int) ([]byte, error) {
	if n < 0 || d.i > len(d.b)-n {
		return nil, io.ErrUnexpectedEOF
	}
	v := d.b[d.i : d.i+n]
	d.i += n
	return v, nil
}
func (d *decoder) u16() (uint16, error) {
	b, err := d.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}
func (d *decoder) u32() (uint32, error) {
	b, err := d.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}
func (d *decoder) u64() (uint64, error) {
	b, err := d.take(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}
func (d *decoder) done() error {
	if d.i != len(d.b) {
		return fmt.Errorf("%w: trailing bytes", ErrInvalidInput)
	}
	return nil
}

func decodeManifest(b []byte, limits Limits) (Manifest, error) {
	limits = limits.normalized()
	if uint64(len(b)) > uint64(limits.MaxManifestBytes) {
		return Manifest{}, fmt.Errorf("%w: manifest bytes", ErrLimitExceeded)
	}
	d := decoder{b: b}
	magic, err := d.take(len(manifestMagic))
	if err != nil || !bytes.Equal(magic, []byte(manifestMagic)) {
		return Manifest{}, fmt.Errorf("%w: manifest magic", ErrInvalidInput)
	}
	v, err := d.u16()
	if err != nil || v != ProtocolVersion {
		return Manifest{}, fmt.Errorf("%w: manifest version", ErrInvalidInput)
	}
	nameLen, err := d.u16()
	if err != nil || nameLen == 0 || nameLen > limits.MaxFilenameBytes {
		return Manifest{}, fmt.Errorf("%w: filename length", ErrLimitExceeded)
	}
	name, err := d.take(int(nameLen))
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: filename: %v", ErrInvalidInput, err)
	}
	size, err := d.u64()
	if err != nil || size > uint64(limits.MaxFileSize) {
		return Manifest{}, fmt.Errorf("%w: file size", ErrLimitExceeded)
	}
	chunkSize, err := d.u32()
	if err != nil || chunkSize == 0 || chunkSize > limits.MaxChunkSize {
		return Manifest{}, fmt.Errorf("%w: chunk size", ErrLimitExceeded)
	}
	count, err := d.u32()
	if err != nil || count > limits.MaxChunks {
		return Manifest{}, fmt.Errorf("%w: chunk count", ErrLimitExceeded)
	}
	expected := uint64(4+2+2) + uint64(nameLen) + 8 + 4 + 4 + sha256.Size + uint64(count)*sha256.Size
	if expected != uint64(len(b)) {
		return Manifest{}, fmt.Errorf("%w: malformed manifest length", ErrInvalidInput)
	}
	content, err := d.take(sha256.Size)
	if err != nil {
		return Manifest{}, err
	}
	m := Manifest{Filename: string(name), Size: int64(size), ChunkSize: chunkSize}
	copy(m.ContentHash[:], content)
	m.ChunkHashes = make([][sha256.Size]byte, count)
	for i := range m.ChunkHashes {
		h, takeErr := d.take(sha256.Size)
		if takeErr != nil {
			return Manifest{}, takeErr
		}
		copy(m.ChunkHashes[i][:], h)
	}
	if err := d.done(); err != nil {
		return Manifest{}, err
	}
	if err := validateManifest(m, limits); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

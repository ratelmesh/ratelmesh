package pqcrypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/shan25519/ratelmesh/internal/atomicfile"
	"github.com/shan25519/ratelmesh/internal/types"
)

const (
	KEMPublicKeySize   = mlkem.EncapsulationKeySize768
	KEMCiphertextSize  = mlkem.CiphertextSize768
	MLDSAPublicKeySize = mldsa65.PublicKeySize
	MLDSASignatureSize = mldsa65.SignatureSize
)

// DeviceKeys are the persistent post-quantum keys of one mesh node. The ML-KEM
// key establishes WireGuard PSKs; ML-DSA authenticates encapsulations so a
// compromised coordinator cannot substitute a ciphertext whose secret it knows.
type DeviceKeys struct {
	kem  *mlkem.DecapsulationKey768
	sign *mldsa65.PrivateKey
}

func LoadOrCreateDeviceKeys(dir string) (*DeviceKeys, error) {
	kemSeed, err := loadOrCreateSeed(filepath.Join(dir, "node.mlkem768"), mlkem.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("load ML-KEM key: %w", err)
	}
	kemKey, err := mlkem.NewDecapsulationKey768(kemSeed)
	if err != nil {
		return nil, fmt.Errorf("parse ML-KEM key: %w", err)
	}
	signSeed, err := loadOrCreateSeed(filepath.Join(dir, "node.mldsa65"), mldsa65.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("load ML-DSA key: %w", err)
	}
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], signSeed)
	_, signKey := mldsa65.NewKeyFromSeed(&seed)
	return &DeviceKeys{kem: kemKey, sign: signKey}, nil
}

func loadOrCreateSeed(path string, size int) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, err
		}
		seed, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(data)))
		if err != nil || len(seed) != size {
			return nil, fmt.Errorf("invalid key seed %s", path)
		}
		return seed, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	seed := make([]byte, size)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := atomicfile.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(seed))); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	return seed, nil
}

func (k *DeviceKeys) KEMPublicKey() []byte {
	return append([]byte(nil), k.kem.EncapsulationKey().Bytes()...)
}

func (k *DeviceKeys) MLDSAPublicKey() []byte {
	return append([]byte(nil), k.sign.Public().(*mldsa65.PublicKey).Bytes()...)
}

func (k *DeviceKeys) Decapsulate(ciphertext []byte) ([]byte, error) {
	return k.kem.Decapsulate(ciphertext)
}

func Encapsulate(publicKey []byte) (sharedKey, ciphertext []byte, err error) {
	key, err := mlkem.NewEncapsulationKey768(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ML-KEM public key: %w", err)
	}
	sharedKey, ciphertext = key.Encapsulate()
	return sharedKey, ciphertext, nil
}

func (k *DeviceKeys) SignSession(initiatorID, recipientID string, ciphertext []byte) ([]byte, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(k.sign, sessionMessage(initiatorID, recipientID, ciphertext), []byte("RatelMesh-PQSession-v1"), false, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

func VerifySession(publicKey []byte, initiatorID, recipientID string, ciphertext, signature []byte) bool {
	if len(publicKey) != mldsa65.PublicKeySize || len(signature) != mldsa65.SignatureSize {
		return false
	}
	var key mldsa65.PublicKey
	if err := key.UnmarshalBinary(publicKey); err != nil {
		return false
	}
	return mldsa65.Verify(&key, sessionMessage(initiatorID, recipientID, ciphertext), []byte("RatelMesh-PQSession-v1"), signature)
}

func sessionMessage(initiatorID, recipientID string, ciphertext []byte) []byte {
	var b bytes.Buffer
	for _, field := range [][]byte{[]byte(initiatorID), []byte(recipientID), ciphertext} {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(field)))
		_, _ = b.Write(field)
	}
	return b.Bytes()
}

// DeriveWireGuardPSK binds the KEM secret to both authenticated node identities,
// both WireGuard keys, and the recipient's KEM key. Reusing a ciphertext in a
// different pair or after a key rotation therefore produces a different PSK.
func DeriveWireGuardPSK(shared []byte, initiatorID, recipientID string, initiatorWG, recipientWG types.Key, recipientKEM []byte) types.Key {
	h := sha256.New()
	_, _ = h.Write([]byte("RatelMesh-WireGuard-MLKEM768-v1\x00"))
	for _, field := range [][]byte{[]byte(initiatorID), []byte(recipientID), initiatorWG[:], recipientWG[:], recipientKEM} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(field)
	}
	salt := h.Sum(nil)
	extract := hmac.New(sha256.New, salt)
	_, _ = extract.Write(shared)
	prk := extract.Sum(nil)
	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write([]byte("wireguard-preshared-key\x01"))
	var out types.Key
	copy(out[:], expand.Sum(nil))
	return out
}

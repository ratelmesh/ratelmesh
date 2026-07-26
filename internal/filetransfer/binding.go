package filetransfer

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"time"
)

var bindingContext = []byte("RatelMesh-File-Transfer-Device-Key-Binding-v2\x00")

const (
	maxTenantIDBytes = 128
	maxDeviceIDBytes = 128
)

// DeviceKeyBinding is an offline Tenant-authority-signed binding between a
// tenant device identity and its dedicated file-transfer keys.
type DeviceKeyBinding struct {
	Version        uint16
	TenantID       string
	DeviceID       string
	SigningPublic  [ed25519.PublicKeySize]byte
	ExchangePublic [x25519KeySize]byte
	KeyVersion     uint64
	NotBeforeUnix  int64
	NotAfterUnix   int64
	AuthorityKeyID [16]byte
	Signature      [ed25519.SignatureSize]byte
}

func (b DeviceKeyBinding) signedBytes() ([]byte, error) {
	if b.Version != ProtocolVersion || len(b.TenantID) == 0 || len(b.TenantID) > maxTenantIDBytes ||
		len(b.DeviceID) == 0 || len(b.DeviceID) > maxDeviceIDBytes ||
		b.KeyVersion == 0 || b.NotBeforeUnix < 0 || b.NotAfterUnix <= b.NotBeforeUnix ||
		allZero(b.SigningPublic[:]) || allZero(b.ExchangePublic[:]) {
		return nil, fmt.Errorf("%w: device key binding", ErrInvalidInput)
	}
	out := make([]byte, 0, len(bindingContext)+2+2+len(b.TenantID)+2+len(b.DeviceID)+32+32+8+8+8+16)
	out = append(out, bindingContext...)
	out = appendU16(out, b.Version)
	out = appendU16(out, uint16(len(b.TenantID)))
	out = append(out, b.TenantID...)
	out = appendU16(out, uint16(len(b.DeviceID)))
	out = append(out, b.DeviceID...)
	out = append(out, b.SigningPublic[:]...)
	out = append(out, b.ExchangePublic[:]...)
	out = appendU64(out, b.KeyVersion)
	out = appendU64(out, uint64(b.NotBeforeUnix))
	out = appendU64(out, uint64(b.NotAfterUnix))
	out = append(out, b.AuthorityKeyID[:]...)
	return out, nil
}

func SignDeviceKeyBinding(binding DeviceKeyBinding, authorityPrivate ed25519.PrivateKey) (DeviceKeyBinding, error) {
	if len(authorityPrivate) != ed25519.PrivateKeySize {
		return DeviceKeyBinding{}, fmt.Errorf("%w: Tenant authority private key", ErrInvalidInput)
	}
	msg, err := binding.signedBytes()
	if err != nil {
		return DeviceKeyBinding{}, err
	}
	copy(binding.Signature[:], ed25519.Sign(authorityPrivate, msg))
	return binding, nil
}

func VerifyDeviceBinding(binding DeviceKeyBinding, authorityPublic ed25519.PublicKey, expectedTenant, expectedDevice string, now time.Time, minimumKeyVersion uint64) (Peer, error) {
	if len(authorityPublic) != ed25519.PublicKeySize || expectedTenant == "" || expectedDevice == "" {
		return Peer{}, fmt.Errorf("%w: binding verifier", ErrInvalidInput)
	}
	msg, err := binding.signedBytes()
	if err != nil {
		return Peer{}, err
	}
	if !ed25519.Verify(authorityPublic, msg, binding.Signature[:]) {
		return Peer{}, ErrAuthentication
	}
	if subtle.ConstantTimeCompare([]byte(binding.TenantID), []byte(expectedTenant)) != 1 ||
		subtle.ConstantTimeCompare([]byte(binding.DeviceID), []byte(expectedDevice)) != 1 {
		return Peer{}, ErrAuthentication
	}
	if binding.KeyVersion < minimumKeyVersion {
		return Peer{}, fmt.Errorf("%w: device key downgrade", ErrAuthentication)
	}
	nowUnix := now.Unix()
	if nowUnix < binding.NotBeforeUnix || nowUnix >= binding.NotAfterUnix {
		return Peer{}, fmt.Errorf("%w: device key outside validity window", ErrAuthentication)
	}
	if _, err := ecdh.X25519().NewPublicKey(binding.ExchangePublic[:]); err != nil {
		return Peer{}, fmt.Errorf("%w: invalid X25519 public key", ErrInvalidInput)
	}
	digest := sha256.Sum256(msg)
	var p Peer
	p.signingPublic = binding.SigningPublic
	p.exchangePublic = binding.ExchangePublic
	p.bindingDigest = digest
	p.tenantID = binding.TenantID
	p.deviceID = binding.DeviceID
	p.keyVersion = binding.KeyVersion
	p.notBefore = time.Unix(binding.NotBeforeUnix, 0)
	p.notAfter = time.Unix(binding.NotAfterUnix, 0)
	return p, nil
}

// OpenLocalDevice verifies the authority binding and proves that the supplied
// private keys are the bound file-transfer keys.
func OpenLocalDevice(binding DeviceKeyBinding, signingPrivate ed25519.PrivateKey, exchangePrivate []byte, authorityPublic ed25519.PublicKey, expectedTenant, expectedDevice string, now time.Time, minimumKeyVersion uint64) (*LocalDevice, error) {
	peer, err := VerifyDeviceBinding(binding, authorityPublic, expectedTenant, expectedDevice, now, minimumKeyVersion)
	if err != nil {
		return nil, err
	}
	if len(signingPrivate) != ed25519.PrivateKeySize || len(exchangePrivate) != x25519KeySize {
		return nil, fmt.Errorf("%w: local device private keys", ErrInvalidInput)
	}
	signPub, ok := signingPrivate.Public().(ed25519.PublicKey)
	if !ok || subtle.ConstantTimeCompare(signPub, peer.signingPublic[:]) != 1 {
		return nil, ErrAuthentication
	}
	xpriv, err := ecdh.X25519().NewPrivateKey(exchangePrivate)
	if err != nil || !bytes.Equal(xpriv.PublicKey().Bytes(), peer.exchangePublic[:]) {
		return nil, ErrAuthentication
	}
	d := &LocalDevice{
		identity: identityMaterial{SigningPrivate: append(ed25519.PrivateKey(nil), signingPrivate...), SigningPublic: append(ed25519.PublicKey(nil), signPub...)},
		peer:     peer,
	}
	copy(d.exchangePrivate[:], exchangePrivate)
	return d, nil
}

func (d *LocalDevice) Close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	d.closed = true
	zero(d.identity.SigningPrivate)
	zero(d.exchangePrivate[:])
}

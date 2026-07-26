package filetransfer

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const (
	transferIDSize = 16
	contentKeySize = 32
	offerNonceSize = 12
	x25519KeySize  = 32
	offerFixedSize = 4 + 2 + transferIDSize + 32*7 + 8 + offerNonceSize + 4 + ed25519.SignatureSize
)

var (
	offerContext = []byte("RatelMesh-File-Transfer-Offer-v2\x00")
	kekContext   = "RatelMesh-File-Transfer-Envelope-KEK-v2\x00"
)

type ExchangeIdentity struct {
	Private []byte
	Public  []byte
}

func GenerateExchangeIdentity(r io.Reader) (ExchangeIdentity, error) {
	if r == nil {
		r = rand.Reader
	}
	k, err := ecdh.X25519().GenerateKey(r)
	if err != nil {
		return ExchangeIdentity{}, fmt.Errorf("generate X25519 key: %w", err)
	}
	return ExchangeIdentity{
		Private: append([]byte(nil), k.Bytes()...),
		Public:  append([]byte(nil), k.PublicKey().Bytes()...),
	}, nil
}

// Offer is safe to pass through an untrusted coordinator. The filename,
// manifest, and content key exist only inside Ciphertext.
type Offer struct {
	Version            uint16
	TransferID         [transferIDSize]byte
	SenderSigning      [ed25519.PublicKeySize]byte
	RecipientSigning   [ed25519.PublicKeySize]byte
	RecipientExchange  [x25519KeySize]byte
	EphemeralExchange  [x25519KeySize]byte
	ManifestCommitment [sha256.Size]byte
	SenderBinding      [sha256.Size]byte
	RecipientBinding   [sha256.Size]byte
	ExpiresAtUnix      int64
	Nonce              [offerNonceSize]byte
	Ciphertext         []byte
	Signature          [ed25519.SignatureSize]byte
}

func (o Offer) publicTranscript() []byte {
	b := make([]byte, 0, len(offerContext)+2+transferIDSize+32*7+8+offerNonceSize)
	b = append(b, offerContext...)
	b = appendU16(b, o.Version)
	b = append(b, o.TransferID[:]...)
	b = append(b, o.SenderSigning[:]...)
	b = append(b, o.RecipientSigning[:]...)
	b = append(b, o.RecipientExchange[:]...)
	b = append(b, o.EphemeralExchange[:]...)
	b = append(b, o.ManifestCommitment[:]...)
	b = append(b, o.SenderBinding[:]...)
	b = append(b, o.RecipientBinding[:]...)
	b = appendU64(b, uint64(o.ExpiresAtUnix))
	b = append(b, o.Nonce[:]...)
	return b
}

func (o Offer) signedTranscript() []byte {
	b := o.publicTranscript()
	b = appendU32(b, uint32(len(o.Ciphertext)))
	b = append(b, o.Ciphertext...)
	return b
}

func (o Offer) MarshalBinary() ([]byte, error) {
	if o.Version != ProtocolVersion || len(o.Ciphertext) == 0 {
		return nil, fmt.Errorf("%w: offer", ErrInvalidInput)
	}
	b := make([]byte, 0, 4+2+transferIDSize+32*7+8+offerNonceSize+4+len(o.Ciphertext)+len(o.Signature))
	b = append(b, offerMagic...)
	b = appendU16(b, o.Version)
	b = append(b, o.TransferID[:]...)
	b = append(b, o.SenderSigning[:]...)
	b = append(b, o.RecipientSigning[:]...)
	b = append(b, o.RecipientExchange[:]...)
	b = append(b, o.EphemeralExchange[:]...)
	b = append(b, o.ManifestCommitment[:]...)
	b = append(b, o.SenderBinding[:]...)
	b = append(b, o.RecipientBinding[:]...)
	b = appendU64(b, uint64(o.ExpiresAtUnix))
	b = append(b, o.Nonce[:]...)
	b = appendU32(b, uint32(len(o.Ciphertext)))
	b = append(b, o.Ciphertext...)
	b = append(b, o.Signature[:]...)
	return b, nil
}

func ParseOffer(b []byte, limits Limits) (Offer, error) {
	limits = limits.normalized()
	if uint64(len(b)) > uint64(limits.MaxOfferBytes) {
		return Offer{}, fmt.Errorf("%w: offer bytes", ErrLimitExceeded)
	}
	if len(b) < offerFixedSize {
		return Offer{}, fmt.Errorf("%w: truncated offer", ErrInvalidInput)
	}
	d := decoder{b: b}
	magic, _ := d.take(4)
	if string(magic) != offerMagic {
		return Offer{}, fmt.Errorf("%w: offer magic", ErrInvalidInput)
	}
	var o Offer
	var err error
	o.Version, err = d.u16()
	if err != nil || o.Version != ProtocolVersion {
		return Offer{}, fmt.Errorf("%w: offer version", ErrInvalidInput)
	}
	for _, dst := range [][]byte{o.TransferID[:], o.SenderSigning[:], o.RecipientSigning[:], o.RecipientExchange[:], o.EphemeralExchange[:], o.ManifestCommitment[:], o.SenderBinding[:], o.RecipientBinding[:]} {
		v, takeErr := d.take(len(dst))
		if takeErr != nil {
			return Offer{}, fmt.Errorf("%w: truncated offer", ErrInvalidInput)
		}
		copy(dst, v)
	}
	expiry, err := d.u64()
	if err != nil || expiry > uint64(^uint64(0)>>1) {
		return Offer{}, fmt.Errorf("%w: offer expiry", ErrInvalidInput)
	}
	o.ExpiresAtUnix = int64(expiry)
	nonce, err := d.take(len(o.Nonce))
	if err != nil {
		return Offer{}, fmt.Errorf("%w: truncated offer", ErrInvalidInput)
	}
	copy(o.Nonce[:], nonce)
	n, err := d.u32()
	maxCiphertext := uint64(limits.MaxManifestBytes) + contentKeySize + 4 + 16
	if err != nil || n == 0 || uint64(n) > maxCiphertext ||
		uint64(n)+uint64(offerFixedSize) != uint64(len(b)) {
		return Offer{}, fmt.Errorf("%w: ciphertext length", ErrInvalidInput)
	}
	c, err := d.take(int(n))
	if err != nil {
		return Offer{}, fmt.Errorf("%w: truncated ciphertext", ErrInvalidInput)
	}
	o.Ciphertext = append([]byte(nil), c...)
	sig, err := d.take(ed25519.SignatureSize)
	if err != nil {
		return Offer{}, fmt.Errorf("%w: truncated signature", ErrInvalidInput)
	}
	copy(o.Signature[:], sig)
	if err := d.done(); err != nil {
		return Offer{}, err
	}
	return o, nil
}

func deriveKEK(shared, transcript []byte) ([]byte, error) {
	salt := sha256.Sum256(transcript)
	return hkdf.Key(sha256.New, shared, salt[:], kekContext, contentKeySize)
}

func envelopeAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create envelope cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create envelope AEAD: %w", err)
	}
	return aead, nil
}

func makeOffer(ctx context.Context, manifest Manifest, contentKey []byte, sender *LocalDevice, recipient Peer, expiresAt time.Time, r io.Reader) (Offer, error) {
	if err := ctx.Err(); err != nil {
		return Offer{}, err
	}
	if r == nil {
		r = rand.Reader
	}
	senderIdentity, _, senderPeer, err := sender.snapshot()
	if err != nil {
		return Offer{}, err
	}
	defer zero(senderIdentity.SigningPrivate)
	if len(senderIdentity.SigningPrivate) != ed25519.PrivateKeySize || len(contentKey) != contentKeySize {
		return Offer{}, fmt.Errorf("%w: identity or key length", ErrInvalidInput)
	}
	if senderPeer.tenantID != recipient.tenantID {
		return Offer{}, fmt.Errorf("%w: cross-tenant transfer requires an explicit guest capability", ErrAuthentication)
	}
	if expiresAt.Unix() <= 0 || expiresAt.After(senderPeer.notAfter) || expiresAt.After(recipient.notAfter) {
		return Offer{}, fmt.Errorf("%w: offer expiry outside device binding", ErrInvalidInput)
	}
	recipientX, err := ecdh.X25519().NewPublicKey(recipient.exchangePublic[:])
	if err != nil {
		return Offer{}, fmt.Errorf("%w: recipient X25519 key", ErrInvalidInput)
	}
	eph, err := ecdh.X25519().GenerateKey(r)
	if err != nil {
		return Offer{}, fmt.Errorf("generate ephemeral key: %w", err)
	}
	shared, err := eph.ECDH(recipientX)
	if err != nil {
		return Offer{}, fmt.Errorf("%w: X25519 agreement", ErrAuthentication)
	}
	defer zero(shared)
	var o Offer
	o.Version = ProtocolVersion
	if _, err := io.ReadFull(r, o.TransferID[:]); err != nil {
		return Offer{}, fmt.Errorf("generate transfer ID: %w", err)
	}
	if allZero(o.TransferID[:]) {
		return Offer{}, fmt.Errorf("%w: zero transfer ID", ErrInvalidInput)
	}
	copy(o.SenderSigning[:], senderPeer.signingPublic[:])
	copy(o.RecipientSigning[:], recipient.signingPublic[:])
	copy(o.RecipientExchange[:], recipient.exchangePublic[:])
	copy(o.EphemeralExchange[:], eph.PublicKey().Bytes())
	o.SenderBinding = senderPeer.bindingDigest
	o.RecipientBinding = recipient.bindingDigest
	o.ExpiresAtUnix = expiresAt.Unix()
	if _, err := io.ReadFull(r, o.Nonce[:]); err != nil {
		return Offer{}, fmt.Errorf("generate envelope nonce: %w", err)
	}
	manifestBytes := encodeManifest(manifest)
	o.ManifestCommitment = manifestCommitment(contentKey, o.TransferID, manifestBytes)
	kek, err := deriveKEK(shared, o.publicTranscript())
	if err != nil {
		return Offer{}, fmt.Errorf("derive envelope key: %w", err)
	}
	defer zero(kek)
	aead, err := envelopeAEAD(kek)
	if err != nil {
		return Offer{}, err
	}
	payload := make([]byte, 0, contentKeySize+4+len(manifestBytes))
	payload = append(payload, contentKey...)
	payload = appendU32(payload, uint32(len(manifestBytes)))
	payload = append(payload, manifestBytes...)
	defer zero(payload)
	o.Ciphertext = aead.Seal(nil, o.Nonce[:], payload, o.publicTranscript())
	copy(o.Signature[:], ed25519.Sign(senderIdentity.SigningPrivate, o.signedTranscript()))
	return o, nil
}

type openedOffer struct {
	manifest   Manifest
	contentKey []byte
}

func openOffer(ctx context.Context, o Offer, recipient *LocalDevice, expectedSender Peer, now time.Time, limits Limits) (openedOffer, error) {
	if err := ctx.Err(); err != nil {
		return openedOffer{}, err
	}
	limits = limits.normalized()
	if o.Version != ProtocolVersion || len(o.Ciphertext) == 0 ||
		uint64(len(o.Ciphertext))+offerFixedSize > uint64(limits.MaxOfferBytes) ||
		uint64(len(o.Ciphertext)) > uint64(limits.MaxManifestBytes)+contentKeySize+4+16 ||
		allZero(o.TransferID[:]) || allZero(o.ManifestCommitment[:]) ||
		allZero(o.SenderBinding[:]) || allZero(o.RecipientBinding[:]) {
		return openedOffer{}, fmt.Errorf("%w: recipient input", ErrInvalidInput)
	}
	recipientIdentity, recipientExchange, recipientPeer, err := recipient.snapshot()
	if err != nil {
		return openedOffer{}, err
	}
	defer zero(recipientIdentity.SigningPrivate)
	if expectedSender.tenantID != recipientPeer.tenantID {
		return openedOffer{}, fmt.Errorf("%w: cross-tenant transfer requires an explicit guest capability", ErrAuthentication)
	}
	if now.Before(expectedSender.notBefore) || now.Before(recipientPeer.notBefore) ||
		now.Unix() >= o.ExpiresAtUnix || o.ExpiresAtUnix <= 0 ||
		o.ExpiresAtUnix > expectedSender.notAfter.Unix() || o.ExpiresAtUnix > recipientPeer.notAfter.Unix() ||
		subtle.ConstantTimeCompare(o.SenderSigning[:], expectedSender.signingPublic[:]) != 1 ||
		subtle.ConstantTimeCompare(o.RecipientSigning[:], recipientPeer.signingPublic[:]) != 1 ||
		subtle.ConstantTimeCompare(o.SenderBinding[:], expectedSender.bindingDigest[:]) != 1 ||
		subtle.ConstantTimeCompare(o.RecipientBinding[:], recipientPeer.bindingDigest[:]) != 1 ||
		!ed25519.Verify(expectedSender.signingPublic[:], o.signedTranscript(), o.Signature[:]) {
		return openedOffer{}, ErrAuthentication
	}
	xpriv, err := ecdh.X25519().NewPrivateKey(recipientExchange[:])
	if err != nil {
		return openedOffer{}, fmt.Errorf("%w: recipient X25519 private key", ErrInvalidInput)
	}
	if subtle.ConstantTimeCompare(xpriv.PublicKey().Bytes(), o.RecipientExchange[:]) != 1 {
		return openedOffer{}, ErrAuthentication
	}
	eph, err := ecdh.X25519().NewPublicKey(o.EphemeralExchange[:])
	if err != nil {
		return openedOffer{}, ErrAuthentication
	}
	shared, err := xpriv.ECDH(eph)
	if err != nil {
		return openedOffer{}, ErrAuthentication
	}
	defer zero(shared)
	kek, err := deriveKEK(shared, o.publicTranscript())
	if err != nil {
		return openedOffer{}, fmt.Errorf("derive envelope key: %w", err)
	}
	defer zero(kek)
	aead, err := envelopeAEAD(kek)
	if err != nil {
		return openedOffer{}, err
	}
	plain, err := aead.Open(nil, o.Nonce[:], o.Ciphertext, o.publicTranscript())
	if err != nil {
		return openedOffer{}, ErrAuthentication
	}
	defer zero(plain)
	if len(plain) < contentKeySize+4 {
		return openedOffer{}, ErrIntegrity
	}
	n := binary.BigEndian.Uint32(plain[contentKeySize : contentKeySize+4])
	if n > limits.normalized().MaxManifestBytes || uint64(n)+contentKeySize+4 != uint64(len(plain)) {
		return openedOffer{}, fmt.Errorf("%w: envelope manifest length", ErrIntegrity)
	}
	m, err := decodeManifest(plain[contentKeySize+4:], limits)
	if err != nil {
		return openedOffer{}, fmt.Errorf("%w: manifest: %v", ErrIntegrity, err)
	}
	if manifestCommitment(plain[:contentKeySize], o.TransferID, plain[contentKeySize+4:]) != o.ManifestCommitment {
		return openedOffer{}, ErrIntegrity
	}
	return openedOffer{manifest: m, contentKey: append([]byte(nil), plain[:contentKeySize]...)}, nil
}

func allZero(b []byte) bool {
	var v byte
	for _, x := range b {
		v |= x
	}
	return v == 0
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

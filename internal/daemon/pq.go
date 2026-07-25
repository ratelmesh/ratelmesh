package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/shan25519/ratelmesh/internal/pqcrypto"
	"github.com/shan25519/ratelmesh/internal/types"
)

func pqCiphertextHash(ciphertext []byte) string {
	sum := sha256.Sum256(ciphertext)
	return base64.RawStdEncoding.EncodeToString(sum[:])
}

func pqSessionFor(nm types.Netmap, peerID string) (types.PQSession, bool) {
	for _, session := range nm.PQSessions {
		if (session.InitiatorID == nm.Self.ID && session.RecipientID == peerID) ||
			(session.InitiatorID == peerID && session.RecipientID == nm.Self.ID) {
			return session, true
		}
	}
	return types.PQSession{}, false
}

// ensurePQSessions creates the canonical smaller-ID -> larger-ID encapsulation
// for every visible PQ-capable peer. Shared secrets are encrypted at rest before
// the ciphertext is published, so a crash cannot strand the initiator.
func (d *Daemon) ensurePQSessions(ctx context.Context, nm types.Netmap) error {
	if !d.cfg.RequirePQC {
		return nil
	}
	for _, peer := range nm.Peers {
		if nm.Self.ID >= peer.ID {
			continue
		}
		if len(peer.PQKEMPublicKey) != pqcrypto.KEMPublicKeySize || len(nm.Self.PQSigningPublicKey) != pqcrypto.MLDSAPublicKeySize {
			if d.cfg.RequirePQC {
				d.log.Warn("peer does not advertise required post-quantum keys", "peer", peer.Name)
			}
			continue
		}
		if current, ok := pqSessionFor(nm, peer.ID); ok {
			d.mu.Lock()
			record, saved := d.pqSecrets[peer.ID]
			d.mu.Unlock()
			if saved && record.CiphertextHash == pqCiphertextHash(current.Ciphertext) {
				continue
			}
		}
		shared, ciphertext, err := pqcrypto.Encapsulate(peer.PQKEMPublicKey)
		if err != nil {
			return err
		}
		signature, err := d.pqKeys.SignSession(nm.Self.ID, peer.ID, ciphertext)
		if err != nil {
			return err
		}
		record := pqSecretRecord{
			CiphertextHash: pqCiphertextHash(ciphertext),
			SharedKey:      base64.RawStdEncoding.EncodeToString(shared),
		}
		d.mu.Lock()
		d.pqSecrets[peer.ID] = record
		secrets := make(map[string]pqSecretRecord, len(d.pqSecrets))
		for id, value := range d.pqSecrets {
			secrets[id] = value
		}
		d.mu.Unlock()
		if err := savePQSecrets(d.cfg.StateDir, d.priv, secrets); err != nil {
			return fmt.Errorf("persist PQ session secret: %w", err)
		}
		if err := d.client.PublishPQSession(ctx, nm.Self.ID, peer.ID, ciphertext, signature); err != nil {
			return fmt.Errorf("publish PQ session for %s: %w", peer.Name, err)
		}
	}
	return nil
}

func (d *Daemon) pqPresharedKey(nm types.Netmap, peer types.Node) (types.Key, bool) {
	session, ok := pqSessionFor(nm, peer.ID)
	if !ok {
		return types.Key{}, !d.cfg.RequirePQC
	}
	if session.InitiatorID >= session.RecipientID || len(session.Ciphertext) != pqcrypto.KEMCiphertextSize {
		return types.Key{}, false
	}
	var initiator, recipient types.Node
	if nm.Self.ID == session.InitiatorID {
		initiator, recipient = nm.Self, peer
	} else {
		initiator, recipient = peer, nm.Self
	}
	if !pqcrypto.VerifySession(initiator.PQSigningPublicKey, session.InitiatorID, session.RecipientID, session.Ciphertext, session.Signature) {
		return types.Key{}, false
	}
	var shared []byte
	var err error
	if nm.Self.ID == session.InitiatorID {
		d.mu.Lock()
		record, found := d.pqSecrets[peer.ID]
		d.mu.Unlock()
		if !found || record.CiphertextHash != pqCiphertextHash(session.Ciphertext) {
			return types.Key{}, false
		}
		shared, err = base64.RawStdEncoding.DecodeString(record.SharedKey)
	} else {
		shared, err = d.pqKeys.Decapsulate(session.Ciphertext)
	}
	if err != nil || len(shared) != 32 || len(recipient.PQKEMPublicKey) != pqcrypto.KEMPublicKeySize {
		return types.Key{}, false
	}
	return pqcrypto.DeriveWireGuardPSK(shared, session.InitiatorID, session.RecipientID,
		initiator.Key, recipient.Key, recipient.PQKEMPublicKey), true
}

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/ratelmesh/ratelmesh/internal/pqcrypto"
	"github.com/ratelmesh/ratelmesh/internal/types"
)

func pqCiphertextHash(ciphertext []byte) string {
	sum := sha256.Sum256(ciphertext)
	return base64.RawStdEncoding.EncodeToString(sum[:])
}

func pqSessionFor(nm types.Netmap, peerID string) (types.PQSession, bool) {
	var found types.PQSession
	matched := false
	for _, session := range nm.PQSessions {
		if (session.InitiatorID == nm.Self.ID && session.RecipientID == peerID) ||
			(session.InitiatorID == peerID && session.RecipientID == nm.Self.ID) {
			if matched {
				return types.PQSession{}, false
			}
			found = session
			matched = true
		}
	}
	return found, matched
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
			if current.Epoch > 0 && saved && record.Epoch == current.Epoch &&
				record.CiphertextHash == pqCiphertextHash(current.Ciphertext) {
				continue
			}
		}
		d.mu.Lock()
		previous := d.pqSecrets[peer.ID]
		d.mu.Unlock()
		epoch := nm.Version
		if epoch <= previous.Epoch {
			if previous.Epoch == ^uint64(0) {
				return fmt.Errorf("PQ session epoch exhausted for %s", peer.Name)
			}
			epoch = previous.Epoch + 1
		}
		shared, ciphertext, err := pqcrypto.Encapsulate(peer.PQKEMPublicKey)
		if err != nil {
			return err
		}
		signature, err := d.pqKeys.SignSession(nm.Self.ID, peer.ID, epoch, ciphertext)
		if err != nil {
			return err
		}
		record := pqSecretRecord{
			Epoch:          epoch,
			CiphertextHash: pqCiphertextHash(ciphertext),
			SharedKey:      base64.RawStdEncoding.EncodeToString(shared),
		}
		for i := range shared {
			shared[i] = 0
		}
		d.mu.Lock()
		secrets := make(map[string]pqSecretRecord, len(d.pqSecrets))
		for id, value := range d.pqSecrets {
			secrets[id] = value
		}
		secrets[peer.ID] = record
		if err := savePQSecrets(d.cfg.StateDir, d.priv, secrets); err != nil {
			d.mu.Unlock()
			return fmt.Errorf("persist PQ session secret: %w", err)
		}
		d.pqSecrets = secrets
		d.mu.Unlock()
		if err := d.client.PublishPQSession(ctx, nm.Self.ID, peer.ID, epoch, ciphertext, signature); err != nil {
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
	if session.InitiatorID >= session.RecipientID || session.Epoch == 0 ||
		len(session.Ciphertext) != pqcrypto.KEMCiphertextSize {
		return types.Key{}, false
	}
	var initiator, recipient types.Node
	if nm.Self.ID == session.InitiatorID {
		initiator, recipient = nm.Self, peer
	} else {
		initiator, recipient = peer, nm.Self
	}
	if !pqcrypto.VerifySession(initiator.PQSigningPublicKey, session.InitiatorID,
		session.RecipientID, session.Epoch, session.Ciphertext, session.Signature) {
		return types.Key{}, false
	}
	var shared []byte
	var err error
	hash := pqCiphertextHash(session.Ciphertext)
	if nm.Self.ID == session.InitiatorID {
		d.mu.Lock()
		record, found := d.pqSecrets[peer.ID]
		d.mu.Unlock()
		if !found || record.Epoch != session.Epoch || record.CiphertextHash != hash {
			return types.Key{}, false
		}
		shared, err = base64.RawStdEncoding.DecodeString(record.SharedKey)
	} else {
		d.mu.Lock()
		record, found := d.pqSecrets[peer.ID]
		switch {
		case found && session.Epoch < record.Epoch:
			d.mu.Unlock()
			return types.Key{}, false
		case found && session.Epoch == record.Epoch && record.CiphertextHash != hash:
			d.mu.Unlock()
			return types.Key{}, false
		case !found || session.Epoch > record.Epoch:
			next := make(map[string]pqSecretRecord, len(d.pqSecrets)+1)
			for id, value := range d.pqSecrets {
				next[id] = value
			}
			next[peer.ID] = pqSecretRecord{Epoch: session.Epoch, CiphertextHash: hash}
			if err := savePQSecrets(d.cfg.StateDir, d.priv, next); err != nil {
				d.mu.Unlock()
				return types.Key{}, false
			}
			d.pqSecrets = next
		}
		d.mu.Unlock()
		shared, err = d.pqKeys.Decapsulate(session.Ciphertext)
	}
	if err != nil || len(shared) != 32 || len(recipient.PQKEMPublicKey) != pqcrypto.KEMPublicKeySize {
		return types.Key{}, false
	}
	psk := pqcrypto.DeriveWireGuardPSK(shared, session.InitiatorID, session.RecipientID, session.Epoch,
		initiator.Key, recipient.Key, recipient.PQKEMPublicKey)
	for i := range shared {
		shared[i] = 0
	}
	return psk, true
}

package filetransfer

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"os"
)

var consumedContext = []byte("RatelMesh-File-Transfer-Consumed-v2\x00")

const consumedSize = 4 + 2 + transferIDSize + sha256.Size*5 + 8 + sha256.Size

func (r *Receiver) consumedBytes() []byte {
	b := append([]byte{}, "RMFC"...)
	b = appendU16(b, ProtocolVersion)
	b = append(b, r.offer.TransferID[:]...)
	b = append(b, r.offer.ManifestCommitment[:]...)
	b = append(b, r.offer.SenderBinding[:]...)
	b = append(b, r.offer.RecipientBinding[:]...)
	b = append(b, r.manifest.ContentHash[:]...)
	b = appendU64(b, uint64(r.offer.ExpiresAtUnix))
	m := hmac.New(sha256.New, r.resumeKey)
	_, _ = m.Write(consumedContext)
	_, _ = m.Write(b)
	b = append(b, m.Sum(nil)...)
	return b
}

func (r *Receiver) verifyConsumed(name string) (bool, error) {
	data, err := readBoundedRootFile(r.transferRoot, name, consumedSize)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	expected := r.consumedBytes()
	if len(data) != len(expected) || subtle.ConstantTimeCompare(data, expected) != 1 {
		return false, ErrAuthentication
	}
	return true, nil
}

func (r *Receiver) stageConsumed() error {
	if valid, err := r.verifyConsumed("consumed.pending"); err != nil {
		return err
	} else if valid {
		return nil
	}
	if err := atomicWriteState(r.transferRoot, "consumed.pending", r.consumedBytes()); err != nil {
		return fmt.Errorf("stage consumed tombstone: %w", err)
	}
	return nil
}

func (r *Receiver) commitConsumed() error {
	if valid, err := r.verifyConsumed("consumed.state"); err != nil {
		return err
	} else if valid {
		return nil
	}
	if valid, err := r.verifyConsumed("consumed.pending"); err != nil || !valid {
		if err != nil {
			return err
		}
		return ErrIntegrity
	}
	if err := r.transferRoot.Rename("consumed.pending", "consumed.state"); err != nil {
		return fmt.Errorf("publish consumed tombstone: %w", err)
	}
	if err := syncRootDir(r.transferRoot); err != nil {
		return fmt.Errorf("sync consumed tombstone: %w", err)
	}
	return nil
}

package daemon

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shan25519/ratelmesh/internal/types"
)

const machineBindingFile = "machine.binding"

// loadMachineIdentity derives a coordinator-safe binding from the physical
// machine identifier and this node key. Salting with the node key prevents two
// coordinators or two RatelMesh identities from correlating the raw hardware
// identifier. Platforms without a readable hardware ID get an installation ID
// in the protected state directory as a compatibility fallback.
func loadMachineIdentity(stateDir string, nodeKey types.Key) (string, error) {
	machineID, err := platformMachineID()
	if err != nil {
		return "", err
	}
	if machineID == "" {
		machineID, err = loadOrCreateInstallationID(stateDir)
		if err != nil {
			return "", err
		}
	}
	return deriveMachineIdentity(machineID, nodeKey), nil
}

func deriveMachineIdentity(machineID string, nodeKey types.Key) string {
	h := sha256.New()
	_, _ = h.Write([]byte("ratelmesh-physical-machine-v1\x00"))
	_, _ = h.Write([]byte(strings.TrimSpace(machineID)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(nodeKey[:])
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func loadOrCreateInstallationID(stateDir string) (string, error) {
	path := filepath.Join(stateDir, machineBindingFile)
	if data, err := readOptionalStateFile(path); err != nil {
		return "", err
	} else if value := strings.TrimSpace(string(data)); value != "" {
		return value, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate installation identity: %w", err)
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	if err := writeNewKey(path, value); err != nil {
		if !os.IsExist(err) {
			return "", fmt.Errorf("persist installation identity: %w", err)
		}
		data, readErr := readOptionalStateFile(path)
		if readErr != nil {
			return "", readErr
		}
		value = strings.TrimSpace(string(data))
	}
	if value == "" {
		return "", fmt.Errorf("installation identity is empty")
	}
	return value, nil
}

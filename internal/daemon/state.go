package daemon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ratelmesh/ratelmesh/internal/atomicfile"
	"github.com/ratelmesh/ratelmesh/internal/control"
	"github.com/ratelmesh/ratelmesh/internal/types"
)

// persistentState is the small amount of identity ratelmeshd keeps across restarts:
// the device private key (never leaves the machine, DESIGN.md §5) and the node
// ID the coord assigned. On desktop this belongs in the OS keychain; M1 uses a
// 0600 file in the state directory.
type persistentState struct {
	PrivateKey       types.Key
	NodeID           string
	SessionToken     string
	PreferredExit    string
	InternetFallback bool
}

const (
	keyFile      = "node.key"
	idFile       = "node.id"
	tokenFile    = "session.token"
	exitFile     = "preferred-exit"
	fallbackFile = "internet-fallback"
	netmapFile   = "netmap-lkg.json"
	pqSecretFile = "pq-session-secrets.json"
	cleanupFile  = "cleanup-pending"
)

func cleanupPendingState(dir string) (bool, error) {
	_, err := os.Stat(filepath.Join(dir, cleanupFile))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

func persistCleanupPending(dir string) error {
	return atomicfile.WriteFile(filepath.Join(dir, cleanupFile), []byte("v1\n"))
}

func clearCleanupPending(dir string) error {
	err := os.Remove(filepath.Join(dir, cleanupFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

type pqSecretRecord struct {
	Epoch          uint64 `json:"epoch"`
	CiphertextHash string `json:"ciphertextHash"`
	SharedKey      string `json:"sharedKey"`
}

type pqSecretEnvelope struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func pqSecretAEAD(priv types.Key) (cipher.AEAD, error) {
	h := sha256.New()
	_, _ = h.Write([]byte("ratelmesh-pq-session-store-v1\x00"))
	_, _ = h.Write(priv[:])
	block, err := aes.NewCipher(h.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func loadPQSecrets(dir string, priv types.Key) (map[string]pqSecretRecord, error) {
	path := filepath.Join(dir, pqSecretFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return make(map[string]pqSecretRecord), nil
	}
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	var envelope pqSecretEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}
	nonce, err := base64.RawStdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, err
	}
	aead, err := pqSecretAEAD(priv)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, []byte("RatelMesh-PQSecrets-v1"))
	if err != nil {
		return nil, fmt.Errorf("decrypt PQ session secrets: %w", err)
	}
	secrets := make(map[string]pqSecretRecord)
	if err := json.Unmarshal(plain, &secrets); err != nil {
		return nil, err
	}
	return secrets, nil
}

func savePQSecrets(dir string, priv types.Key, secrets map[string]pqSecretRecord) error {
	plain, err := json.Marshal(secrets)
	if err != nil {
		return err
	}
	aead, err := pqSecretAEAD(priv)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ciphertext := aead.Seal(nil, nonce, plain, []byte("RatelMesh-PQSecrets-v1"))
	data, err := json.Marshal(pqSecretEnvelope{
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(filepath.Join(dir, pqSecretFile), data)
}

const (
	netmapCacheSchema  = 1
	maxNetmapCacheSize = 8 << 20
)

// cachedNetmapPayload is authenticated with a key derived from the device's
// private WireGuard key. Binding the snapshot to the coordinator, device and
// configured role prevents a copied state directory from silently authorizing
// a different installation or an offline role escalation.
type cachedNetmapPayload struct {
	Schema   int            `json:"schema"`
	CoordURL string         `json:"coordURL"`
	NodeKey  string         `json:"nodeKey"`
	Role     types.NodeRole `json:"role"`
	Netmap   types.Netmap   `json:"netmap"`
}

type cachedNetmapEnvelope struct {
	cachedNetmapPayload
	MAC string `json:"mac"`
}

func enrollmentRequired(nodeID, sessionToken, authKey string) bool {
	return strings.TrimSpace(nodeID) == "" &&
		strings.TrimSpace(sessionToken) == "" &&
		strings.TrimSpace(authKey) == ""
}

// enrollmentInvalidated reports whether a registration failure means the stored
// credentials can no longer authenticate this node, so the user must enroll
// again. Without this the enrollment prompt latches off after the first
// successful registration and never returns, even once the node is revoked.
//
// It keys on the stable error Code rather than the HTTP status on purpose:
// "proof_required" is also 401 but is an ordinary protocol step the client
// retries by itself, and a transient network failure must never tell an offline
// user to re-enroll.
func enrollmentInvalidated(err error) bool {
	var apiErr *control.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.Code {
	case "unauthorized", "session_required", "machine_identity_conflict":
		return true
	default:
		return false
	}
}

// loadOrCreateState reads the device identity from dir, generating and
// persisting a fresh key on first run.
func loadOrCreateState(dir string) (persistentState, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return persistentState{}, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return persistentState{}, fmt.Errorf("secure state directory: %w", err)
	}
	var st persistentState

	keyPath := filepath.Join(dir, keyFile)
	b, err := os.ReadFile(keyPath)
	switch {
	case err == nil:
		if err := os.Chmod(keyPath, 0o600); err != nil {
			return persistentState{}, fmt.Errorf("secure device key: %w", err)
		}
		k, err := types.ParseKey(strings.TrimSpace(string(b)))
		if err != nil || k.IsZero() {
			return persistentState{}, fmt.Errorf("invalid device key %s: refusing to replace the existing identity", keyPath)
		}
		st.PrivateKey = k
	case os.IsNotExist(err):
		k, err := types.GenerateKey()
		if err != nil {
			return persistentState{}, err
		}
		if err := writeNewKey(keyPath, k.String()); err != nil {
			// Another daemon may have won the O_EXCL race. Load that identity
			// instead of letting two processes proceed with different keys.
			if !os.IsExist(err) {
				return persistentState{}, err
			}
			return loadOrCreateState(dir)
		}
		st.PrivateKey = k
	default:
		return persistentState{}, fmt.Errorf("read device key: %w", err)
	}

	if b, err := readOptionalStateFile(filepath.Join(dir, idFile)); err != nil {
		return persistentState{}, err
	} else {
		st.NodeID = strings.TrimSpace(string(b))
	}
	if b, err := readOptionalStateFile(filepath.Join(dir, tokenFile)); err != nil {
		return persistentState{}, err
	} else {
		st.SessionToken = strings.TrimSpace(string(b))
	}
	if b, err := readOptionalStateFile(filepath.Join(dir, exitFile)); err != nil {
		return persistentState{}, err
	} else {
		st.PreferredExit = strings.TrimSpace(string(b))
	}
	if b, err := readOptionalStateFile(filepath.Join(dir, fallbackFile)); err != nil {
		return persistentState{}, err
	} else {
		st.InternetFallback = strings.TrimSpace(string(b)) == "true"
	}
	return st, nil
}

func writeNewKey(path, key string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(key); err != nil {
		f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return atomicfile.SyncDir(filepath.Dir(path))
}

func readOptionalStateFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state file %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("secure state file %s: %w", path, err)
	}
	return b, nil
}

func writeStateFile(path, value string) error {
	return atomicfile.WriteFile(path, []byte(value))
}

// saveNodeID persists the coord-assigned node ID.
func saveNodeID(dir, id string) error {
	return writeStateFile(filepath.Join(dir, idFile), id)
}

// saveSessionToken persists the session token so re-registration after a daemon
// restart can prove node ownership (security review §1).
func saveSessionToken(dir, token string) error {
	if token == "" {
		return nil
	}
	return writeStateFile(filepath.Join(dir, tokenFile), token)
}

func savePreferredExit(dir, nameOrIP string) error {
	return writeStateFile(filepath.Join(dir, exitFile), strings.TrimSpace(nameOrIP))
}

func saveInternetFallback(dir string, enabled bool) error {
	return writeStateFile(filepath.Join(dir, fallbackFile), fmt.Sprintf("%t", enabled))
}

func normalizedCoordURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

func netmapCacheMAC(priv types.Key, payload []byte) []byte {
	mac := hmac.New(sha256.New, priv[:])
	mac.Write([]byte("ratelmesh-netmap-lkg-v1\x00"))
	mac.Write(payload)
	return mac.Sum(nil)
}

func validateCacheableNetmap(priv types.Key, role types.NodeRole, nm types.Netmap) error {
	if nm.Version == 0 {
		return fmt.Errorf("netmap version is zero")
	}
	if nm.Self.ID == "" || len(nm.Self.MeshIPs) == 0 {
		return fmt.Errorf("netmap self identity is incomplete")
	}
	if nm.Self.Key != priv.Public() {
		return fmt.Errorf("netmap self key does not match device identity")
	}
	return nil
}

// saveCachedNetmap atomically persists the last netmap that the data plane
// successfully accepted. The MAC detects corruption and local cross-project
// substitution; the monotonically increasing Netmap.Version is enforced by
// applyNetmap before a new snapshot can replace this one.
func saveCachedNetmap(dir, coordURL string, priv types.Key, role types.NodeRole, nm types.Netmap) error {
	if err := validateCacheableNetmap(priv, role, nm); err != nil {
		return err
	}
	payload := cachedNetmapPayload{
		Schema: netmapCacheSchema, CoordURL: normalizedCoordURL(coordURL),
		NodeKey: priv.Public().String(), Role: role, Netmap: nm,
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode cached netmap: %w", err)
	}
	envelope := cachedNetmapEnvelope{
		cachedNetmapPayload: payload,
		MAC:                 base64.RawStdEncoding.EncodeToString(netmapCacheMAC(priv, canonical)),
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode cached netmap envelope: %w", err)
	}
	return atomicfile.WriteFile(filepath.Join(dir, netmapFile), data)
}

// loadCachedNetmap verifies and returns the durable last-known-good snapshot.
// Invalid state is never applied; callers may still contact the coordinator to
// recover online rather than replacing the device identity or failing open.
func loadCachedNetmap(dir, coordURL string, priv types.Key, role types.NodeRole) (types.Netmap, error) {
	path := filepath.Join(dir, netmapFile)
	f, err := os.Open(path)
	if err != nil {
		return types.Netmap{}, err
	}
	defer f.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		return types.Netmap{}, fmt.Errorf("secure cached netmap: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxNetmapCacheSize+1))
	if err != nil {
		return types.Netmap{}, fmt.Errorf("read cached netmap: %w", err)
	}
	if len(data) > maxNetmapCacheSize {
		return types.Netmap{}, fmt.Errorf("cached netmap exceeds %d bytes", maxNetmapCacheSize)
	}
	var envelope cachedNetmapEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return types.Netmap{}, fmt.Errorf("decode cached netmap: %w", err)
	}
	if envelope.Schema != netmapCacheSchema {
		return types.Netmap{}, fmt.Errorf("unsupported cached netmap schema %d", envelope.Schema)
	}
	if envelope.CoordURL != normalizedCoordURL(coordURL) {
		return types.Netmap{}, fmt.Errorf("cached netmap belongs to coordinator %q", envelope.CoordURL)
	}
	if envelope.NodeKey != priv.Public().String() {
		return types.Netmap{}, fmt.Errorf("cached netmap belongs to another device")
	}
	if envelope.Role != role {
		return types.Netmap{}, fmt.Errorf("cached netmap belongs to role %q", envelope.Role)
	}
	canonical, err := json.Marshal(envelope.cachedNetmapPayload)
	if err != nil {
		return types.Netmap{}, fmt.Errorf("encode cached netmap for verification: %w", err)
	}
	wantMAC, err := base64.RawStdEncoding.DecodeString(envelope.MAC)
	if err != nil || !hmac.Equal(wantMAC, netmapCacheMAC(priv, canonical)) {
		return types.Netmap{}, fmt.Errorf("cached netmap authentication failed")
	}
	if err := validateCacheableNetmap(priv, role, envelope.Netmap); err != nil {
		return types.Netmap{}, fmt.Errorf("invalid cached netmap: %w", err)
	}
	return envelope.Netmap, nil
}

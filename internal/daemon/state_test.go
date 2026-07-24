package daemon

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratelmesh/ratelmesh/internal/control"
	"github.com/ratelmesh/ratelmesh/internal/routing"
	"github.com/ratelmesh/ratelmesh/internal/types"
)

func TestMachineIdentityIsBoundToHardwareAndNodeKey(t *testing.T) {
	keyA, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	a := deriveMachineIdentity("machine-a", keyA.Public())
	if again := deriveMachineIdentity("machine-a", keyA.Public()); again != a {
		t.Fatalf("machine identity is unstable: %q != %q", a, again)
	}
	if deriveMachineIdentity("machine-b", keyA.Public()) == a {
		t.Fatal("different hardware produced the same binding")
	}
	if deriveMachineIdentity("machine-a", keyB.Public()) == a {
		t.Fatal("different node keys produced a linkable binding")
	}
	raw, err := base64.RawURLEncoding.DecodeString(a)
	if err != nil || len(raw) != 32 {
		t.Fatalf("binding is not a 32-byte base64url hash: %q err=%v", a, err)
	}
}

func TestStateIdentityPersistsWithPrivatePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	first, err := loadOrCreateState(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.PrivateKey != second.PrivateKey {
		t.Fatal("device identity changed across reload")
	}
	if got := fileMode(t, dir); got != 0o700 {
		t.Fatalf("state directory mode = %o, want 700", got)
	}
	if got := fileMode(t, filepath.Join(dir, keyFile)); got != 0o600 {
		t.Fatalf("key mode = %o, want 600", got)
	}

	if err := saveNodeID(dir, "n-test"); err != nil {
		t.Fatal(err)
	}
	if err := saveSessionToken(dir, "token-test"); err != nil {
		t.Fatal(err)
	}
	if err := savePreferredExit(dir, "tokyo-exit"); err != nil {
		t.Fatal(err)
	}
	if err := saveInternetFallback(dir, true); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadOrCreateState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.NodeID != "n-test" || loaded.SessionToken != "token-test" || loaded.PreferredExit != "tokyo-exit" || !loaded.InternetFallback {
		t.Fatalf("state round trip = node %q token %q exit %q fallback %v", loaded.NodeID, loaded.SessionToken, loaded.PreferredExit, loaded.InternetFallback)
	}
	for _, name := range []string{idFile, tokenFile, exitFile, fallbackFile} {
		if got := fileMode(t, filepath.Join(dir, name)); got != 0o600 {
			t.Errorf("%s mode = %o, want 600", name, got)
		}
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "missing coord", cfg: Config{StateDir: t.TempDir()}},
		{name: "bad coord scheme", cfg: Config{CoordURL: "ftp://coord.example", StateDir: t.TempDir()}},
		{name: "missing state", cfg: Config{CoordURL: "https://coord.example"}},
		{name: "bad role", cfg: Config{CoordURL: "https://coord.example", StateDir: t.TempDir(), Role: types.NodeRole("router-ish")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg); err == nil {
				t.Fatal("New accepted invalid configuration")
			}
		})
	}
}

func TestNewReportsEnrollmentRequiredForFreshState(t *testing.T) {
	d, err := New(Config{
		CoordURL: "https://coord.example",
		StateDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Status().EnrollmentRequired {
		t.Fatal("fresh daemon did not report that enrollment is required")
	}
}

func TestNewDoesNotReportEnrollmentRequiredWithAuthKey(t *testing.T) {
	d, err := New(Config{
		CoordURL: "https://coord.example",
		StateDir: t.TempDir(),
		AuthKey:  "ratelmesh-ab12-cd34-ef56",
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Status().EnrollmentRequired {
		t.Fatal("daemon reported enrollment required while an auth key is pending")
	}
}

func TestValidateRoleConfig(t *testing.T) {
	split, err := routing.Parse([]byte(`{"rules":[{"cidrs":["192.168.0.0/16"],"action":"direct"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		cfg     Config
		goos    string
		wantErr bool
	}{
		{name: "cloud-managed nat permission", cfg: Config{EnableNAT: true, Role: types.RolePlain}, goos: "linux"},
		{name: "nat with exit role", cfg: Config{EnableNAT: true, Role: types.RoleExit}, goos: "linux"},
		{name: "routes without subnet-router role", cfg: Config{AdvertiseRoutes: []string{"10.0.0.0/24"}, Role: types.RolePlain}, goos: "linux", wantErr: true},
		{name: "routes with subnet-router role", cfg: Config{AdvertiseRoutes: []string{"10.0.0.0/24"}, Role: types.RoleSubnetRouter}, goos: "linux"},
		{name: "windows kill-switch with direct rules", cfg: Config{Role: types.RolePlain, KillSwitch: true, SplitTunnel: split}, goos: "windows", wantErr: true},
		{name: "linux kill-switch with direct rules", cfg: Config{Role: types.RolePlain, KillSwitch: true, SplitTunnel: split}, goos: "linux"},
		{name: "windows kill-switch without split tunnel", cfg: Config{Role: types.RolePlain, KillSwitch: true}, goos: "windows"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRoleConfig(tt.cfg, tt.goos)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateRoleConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCorruptDeviceKeyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, keyFile)
	const corrupt = "not-a-private-key"
	if err := os.WriteFile(path, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadOrCreateState(dir)
	if err == nil || !strings.Contains(err.Error(), "refusing to replace") {
		t.Fatalf("load corrupt key error = %v, want fail-closed identity error", err)
	}
	b, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(b) != corrupt {
		t.Fatalf("corrupt key was silently replaced with %q", b)
	}
}

func TestCachedNetmapRoundTripAuthenticationAndBinding(t *testing.T) {
	dir := t.TempDir()
	st, err := loadOrCreateState(dir)
	if err != nil {
		t.Fatal(err)
	}
	nm := types.Netmap{
		Version: 17,
		Self: types.Node{
			ID: "node-1", Name: "laptop", Key: st.PrivateKey.Public(), Role: types.RolePlain,
			MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.7")},
		},
	}
	const coordURL = "https://control.example.com/"
	if err := saveCachedNetmap(dir, coordURL, st.PrivateKey, types.RolePlain, nm); err != nil {
		t.Fatal(err)
	}
	if got := fileMode(t, filepath.Join(dir, netmapFile)); got != 0o600 {
		t.Fatalf("cache mode = %o, want 600", got)
	}
	loaded, err := loadCachedNetmap(dir, "https://control.example.com", st.PrivateKey, types.RolePlain)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != nm.Version || loaded.Self.Key != nm.Self.Key {
		t.Fatalf("loaded cache = %+v, want version %d self %s", loaded, nm.Version, nm.Self.Key.ShortString())
	}
	if _, err := loadCachedNetmap(dir, "https://other.example.com", st.PrivateKey, types.RolePlain); err == nil {
		t.Fatal("cache accepted for another coordinator")
	}
	if _, err := loadCachedNetmap(dir, coordURL, st.PrivateKey, types.RoleExit); err == nil {
		t.Fatal("cache accepted for another configured role")
	}
}

func TestCachedNetmapRejectsTamperingAndAnotherDevice(t *testing.T) {
	dir := t.TempDir()
	st, err := loadOrCreateState(dir)
	if err != nil {
		t.Fatal(err)
	}
	nm := types.Netmap{
		Version: 4,
		Self: types.Node{
			ID: "node-1", Key: st.PrivateKey.Public(), Role: types.RolePlain,
			MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.8")},
		},
	}
	const coordURL = "https://control.example.com"
	if err := saveCachedNetmap(dir, coordURL, st.PrivateKey, types.RolePlain, nm); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, netmapFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope cachedNetmapEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Netmap.Self.MeshIPs[0] = netip.MustParseAddr("100.64.0.99")
	tampered, err := json.Marshal(envelope) // deliberately retain the old MAC
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCachedNetmap(dir, coordURL, st.PrivateKey, types.RolePlain); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("tampered cache error = %v, want authentication failure", err)
	}

	other, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadCachedNetmap(dir, coordURL, other, types.RolePlain); err == nil {
		t.Fatal("cache accepted for another device")
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestEnrollmentRequired(t *testing.T) {
	tests := []struct {
		name         string
		nodeID       string
		sessionToken string
		authKey      string
		want         bool
	}{
		{name: "fresh install", want: true},
		{name: "whitespace only", nodeID: " ", sessionToken: "\t", authKey: "\n", want: true},
		{name: "registered node", nodeID: "node-1"},
		{name: "persisted session", sessionToken: "session-1"},
		{name: "pending auth key", authKey: "join-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := enrollmentRequired(tt.nodeID, tt.sessionToken, tt.authKey); got != tt.want {
				t.Fatalf("enrollmentRequired(%q, %q, %q) = %v, want %v", tt.nodeID, tt.sessionToken, tt.authKey, got, tt.want)
			}
		})
	}
}

// TestEnrollmentInvalidatedOnlyForCredentialFailures pins the distinction the
// enrollment prompt depends on: a revoked node must re-arm it, but an
// unreachable coordinator must not — telling every offline user to re-enroll
// would be worse than the stale flag this replaced. "proof_required" is 401 too,
// yet the client recovers from it on its own.
func TestEnrollmentInvalidatedOnlyForCredentialFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"invalid auth key", &control.APIError{Status: 401, Code: "unauthorized"}, true},
		{"revoked session", &control.APIError{Status: 401, Code: "session_required"}, true},
		{"copied node state", &control.APIError{Status: 409, Code: "machine_identity_conflict"}, true},
		{"proof step", &control.APIError{Status: 401, Code: "proof_required"}, false},
		{"coord down", &control.APIError{Status: 503, Code: "state_unavailable"}, false},
		{"network error", errors.New("dial tcp: connection refused"), false},
		{"nil", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := enrollmentInvalidated(tc.err); got != tc.want {
				t.Fatalf("enrollmentInvalidated(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

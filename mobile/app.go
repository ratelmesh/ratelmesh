// Package mobile is the gomobile binding surface for RatelMesh's iOS and Android
// clients (DESIGN.md §10.1). `gomobile bind` turns it into a native framework
// (.xcframework / .aar) that the platform app drives. The heavy lifting reuses
// the shared Go core (internal/daemon); the platform app supplies the VPN
// tunnel (NEPacketTunnelProvider on iOS, VpnService on Android) — wired to the
// real wgengine in a privileged build. Here the API surface is deliberately
// small and gomobile-safe (only strings, ints, errors cross the boundary).
package mobile

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/ratelmesh/ratelmesh/internal/daemon"
	"github.com/ratelmesh/ratelmesh/internal/diagnose"
	"github.com/ratelmesh/ratelmesh/internal/sign"
)

// App is the handle the mobile app holds for the lifetime of the VPN session.
type App struct {
	d        *daemon.Daemon
	engine   *bindingEngine
	mu       sync.Mutex
	cancel   context.CancelFunc
	done     chan struct{}
	stopping bool
	lastErr  string
	doctor   *daemon.NetworkDoctor
}

type appOptions struct {
	CoordURL   string `json:"coordURL"`
	AuthKey    string `json:"authKey"`
	StateDir   string `json:"stateDir"`
	Hostname   string `json:"hostname"`
	ListenPort int    `json:"listenPort,omitempty"`
	// Endpoints are native-discovered candidates for the UDP socket that the
	// platform WireGuard provider will own. Mobile cannot STUN that socket from
	// the gomobile process, so Android/iOS may discover the mapping immediately
	// before bringing the provider up and pass it here.
	Endpoints   []string `json:"endpoints,omitempty"`
	DNSServers  []string `json:"dnsServers,omitempty"`
	RelayAddr   string   `json:"relayAddr,omitempty"`
	ForceRelay  bool     `json:"forceRelay,omitempty"`
	VerifyKey   string   `json:"verifyKey,omitempty"`
	VerifyPQKey string   `json:"verifyPQKey,omitempty"`
	// CoordTransport ("wss") carries the coordinator connection inside a
	// camouflage transport for censored networks; empty keeps plain HTTPS.
	// CoordFrontDoor is the host:port that transport dials (CDN edge), defaulting
	// to the coordinator host on :443.
	CoordTransport string `json:"coordTransport,omitempty"`
	CoordFrontDoor string `json:"coordFrontDoor,omitempty"`
}

// NewApp constructs an app bound to a coordinator. stateDir must be a writable
// path the platform provides (app container). authKey may be empty for dev.
func NewApp(coordURL, authKey, stateDir, hostname string) (*App, error) {
	return newApp(appOptions{
		CoordURL: coordURL, AuthKey: authKey, StateDir: stateDir, Hostname: hostname,
	})
}

// NewAppWithOptions constructs a mobile client from a JSON object. It keeps the
// gomobile surface stable while allowing native apps to opt into DNS, relay and
// key-authority settings without a growing positional argument list.
func NewAppWithOptions(optionsJSON string) (*App, error) {
	var opts appOptions
	if err := json.Unmarshal([]byte(optionsJSON), &opts); err != nil {
		return nil, fmt.Errorf("mobile: parse options: %w", err)
	}
	return newApp(opts)
}

func newApp(opts appOptions) (*App, error) {
	if opts.ListenPort < 0 || opts.ListenPort > 65535 {
		return nil, fmt.Errorf("mobile: listenPort must be between 0 and 65535")
	}
	// Zero is resolved by daemon.New from the persisted node identity. Native
	// clients that perform STUN before startup (Android) pass their own persisted
	// port explicitly so discovery and WireGuard always use the same socket.
	if len(opts.Endpoints) > 16 {
		return nil, fmt.Errorf("mobile: too many endpoint candidates")
	}
	seenEndpoints := make(map[string]bool, len(opts.Endpoints))
	endpoints := make([]string, 0, len(opts.Endpoints))
	for _, candidate := range opts.Endpoints {
		ap, err := netip.ParseAddrPort(candidate)
		if err != nil || !ap.Addr().IsValid() || ap.Port() == 0 {
			return nil, fmt.Errorf("mobile: invalid endpoint candidate %q", candidate)
		}
		canonical := ap.String()
		if !seenEndpoints[canonical] {
			seenEndpoints[canonical] = true
			endpoints = append(endpoints, canonical)
		}
	}
	var verifyKey ed25519.PublicKey
	var verifyPQKey *mldsa65.PublicKey
	if opts.VerifyKey != "" {
		key, err := sign.ParsePublicKey(opts.VerifyKey)
		if err != nil {
			return nil, fmt.Errorf("mobile: verifyKey: %w", err)
		}
		verifyKey = key
	}
	if opts.VerifyPQKey != "" {
		key, err := sign.ParsePQPublicKey(opts.VerifyPQKey)
		if err != nil {
			return nil, fmt.Errorf("mobile: verifyPQKey: %w", err)
		}
		verifyPQKey = key
	}
	engine := newBindingEngine(opts.DNSServers)
	d, err := daemon.New(daemon.Config{
		CoordURL:       opts.CoordURL,
		AuthKey:        opts.AuthKey,
		StateDir:       opts.StateDir,
		Hostname:       opts.Hostname,
		ListenPort:     uint16(opts.ListenPort),
		ExtraEndpoints: endpoints,
		RelayAddr:      opts.RelayAddr,
		ForceRelay:     opts.ForceRelay,
		VerifyKey:      verifyKey,
		VerifyPQKey:    verifyPQKey,
		RequirePQC:     true,
		DisableDisco:   true, // the native tunnel provider owns the UDP socket
		CoordTransport: opts.CoordTransport,
		CoordFrontDoor: opts.CoordFrontDoor,
		Engine:         engine,
	})
	if err != nil {
		return nil, err
	}
	return &App{d: d, engine: engine, doctor: d.NetworkDoctor()}, nil
}

// PublicKey returns this device's WireGuard public key (base64).
func (a *App) PublicKey() string { return a.d.PublicKey().String() }

// Start brings the mesh up in the background. It returns immediately.
func (a *App) Start() {
	a.mu.Lock()
	if a.done != nil {
		a.mu.Unlock()
		return
	}
	a.lastErr = ""
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	done := make(chan struct{})
	a.done = done
	a.mu.Unlock()
	go func() {
		err := a.d.Run(ctx)
		close(done)
		a.mu.Lock()
		if err != nil && err != context.Canceled {
			a.lastErr = err.Error()
		} else {
			a.lastErr = ""
		}
		if a.done == done && !a.stopping {
			a.cancel = nil
			a.done = nil
		}
		a.mu.Unlock()
	}()
}

// TunnelConfigJSON returns the versioned WireGuard snapshot the native iOS or
// Android tunnel adapter must apply. The private key appears only while active.
func (a *App) TunnelConfigJSON() string { return a.engine.configJSON() }

// TunnelConfigVersion lets native code skip JSON parsing when nothing changed.
func (a *App) TunnelConfigVersion() int64 { return a.engine.configVersion() }

// UpdatePeerStatsJSON feeds native WireGuard receive counters back into the Go
// path selector. Native clients should call it periodically with an array of
// {publicKey, latestHandshakeUnix, rxBytes}; this preserves direct/relay health
// decisions even though the native VPN framework owns the actual data plane.
func (a *App) UpdatePeerStatsJSON(statsJSON string) error {
	return a.engine.updateStatsJSON(statsJSON)
}

// LastError returns the last terminal background-run error, or an empty string.
func (a *App) LastError() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastErr
}

// Stop tears the session down.
func (a *App) Stop() {
	a.mu.Lock()
	cancel, done := a.cancel, a.done
	if done != nil {
		a.stopping = true
	}
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
		a.mu.Lock()
		if a.done == done {
			a.cancel = nil
			a.done = nil
		}
		a.stopping = false
		a.mu.Unlock()
	}
}

// StatusJSON returns the current status as a JSON string (gomobile cannot pass
// structs, so the app decodes this).
func (a *App) StatusJSON() string {
	b, err := json.Marshal(a.d.Status())
	if err != nil {
		return "{}"
	}
	return string(b)
}

// UseExit routes all traffic through the named exit node.
func (a *App) UseExit(name string) error { return a.d.SetExit(name) }

// ClearExit resumes direct egress.
func (a *App) ClearExit() error { return a.d.ClearExit() }

// SetSystemLocation receives a native, user-authorized location reading. The Go
// core immediately reduces it to a coarse region; exact coordinates are never
// sent to or retained by the coordinator.
func (a *App) SetSystemLocation(latitude, longitude float64) error {
	return a.d.SetSystemLocation(latitude, longitude)
}

// Resolve looks up a MagicDNS name, returning the mesh IP or "".
func (a *App) Resolve(name string) string {
	ip, _ := a.d.Resolve(name)
	return ip
}

// DoctorDisclosureVersion returns the consent revision native UI must show
// before active probes or a repair.
func (a *App) DoctorDisclosureVersion() string {
	return daemon.DoctorDisclosureVersion()
}

// RunNetworkDoctor returns a stable, redacted JSON envelope containing the
// report, repair plan, and an opaque short-lived planID.
func (a *App) RunNetworkDoctor(disclosureVersion string, confirmed bool) (string, error) {
	if a == nil || a.doctor == nil {
		return "", daemon.ErrDoctorInvalidRequest
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return a.doctor.RunJSON(ctx, confirmed, disclosureVersion)
}

// ApplyNetworkDoctorRepair consumes a one-use planID after native UI explicitly
// confirms the selected action. The returned JSON contains only stable,
// redacted execution and rollback status.
func (a *App) ApplyNetworkDoctorRepair(
	planID, action, disclosureVersion string,
	confirmed bool,
) (string, error) {
	if a == nil || a.doctor == nil {
		return "", daemon.ErrDoctorInvalidRequest
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return a.doctor.RepairJSON(
		ctx, planID, diagnose.RepairActionID(action), confirmed, disclosureVersion,
	)
}

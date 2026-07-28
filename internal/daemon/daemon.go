package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/ratelmesh/ratelmesh/internal/control"
	"github.com/ratelmesh/ratelmesh/internal/dns"
	"github.com/ratelmesh/ratelmesh/internal/exitstack"
	"github.com/ratelmesh/ratelmesh/internal/georegion"
	"github.com/ratelmesh/ratelmesh/internal/magicsock"
	"github.com/ratelmesh/ratelmesh/internal/netguard"
	"github.com/ratelmesh/ratelmesh/internal/pqcrypto"
	"github.com/ratelmesh/ratelmesh/internal/relay"
	"github.com/ratelmesh/ratelmesh/internal/remoteaccess"
	"github.com/ratelmesh/ratelmesh/internal/routing"
	"github.com/ratelmesh/ratelmesh/internal/sign"
	"github.com/ratelmesh/ratelmesh/internal/transport"
	"github.com/ratelmesh/ratelmesh/internal/types"
	"github.com/ratelmesh/ratelmesh/internal/wgengine"
)

// meshCIDR is the mesh address space; exit NAT masquerades traffic from it.
const meshCIDR = "100.64.0.0/10"

var (
	// ErrNetmapRollback means the coordinator offered a configuration older than
	// the last authenticated map this device successfully applied.
	ErrNetmapRollback = errors.New("netmap version rollback rejected")
	// ErrNetmapEquivocation means two different configurations claim the same
	// version. Accepting either would make version-based convergence ambiguous.
	ErrNetmapEquivocation = errors.New("different netmaps claim the same version")
	// ErrNetmapIdentity means the coordinator returned a netmap whose Self
	// identity is not bound to this daemon's persisted node key and node ID.
	ErrNetmapIdentity = errors.New("netmap self identity rejected")
)

// Config configures an ratelmeshd instance.
type Config struct {
	CoordURL string
	AuthKey  string
	StateDir string
	Hostname string
	// ListenPort is the WireGuard UDP port. Zero selects a stable per-device
	// port derived from the persisted node identity; a non-zero value is an
	// explicit operator override.
	ListenPort uint16
	// Role/AdvertiseRoutes let this node offer exit or subnet-router service.
	Role            types.NodeRole
	AdvertiseRoutes []string
	// Tags label this device for ACL matching (DESIGN.md §3.1).
	Tags []string
	// STUNAddr, if set, is a STUN server used to discover this device's public
	// endpoint for hole-punching (DESIGN.md §3.2).
	STUNAddr string
	// ExtraEndpoints are additional ip:port candidates to advertise, e.g. a
	// manually-pinned endpoint or a known-good address in tests.
	ExtraEndpoints []string
	// KillSwitch arms fail-closed firewalling while an exit is active (§3.3).
	KillSwitch bool
	// AcceptRoutes opts in to subnet routes advertised by subnet-router peers
	// (DESIGN.md §10.2). Off by default so a rogue advertiser cannot silently
	// capture traffic.
	AcceptRoutes bool
	// EnableNAT makes an exit node actually forward+masquerade mesh traffic to
	// the internet (Linux, root). Only meaningful with Role=exit (§3.3).
	EnableNAT bool
	// DNSAddr, if set, binds the MagicDNS server on this address (e.g. a mesh IP
	// on port 53) so peers can resolve device.user.ratelmesh.net (§3.1).
	DNSAddr string
	// DNSUpstreams are resolvers for names outside the mesh zone. If empty and
	// ManageResolv is set, the pre-existing /etc/resolv.conf servers are reused.
	DNSUpstreams []string
	// ManageResolv points /etc/resolv.conf at the MagicDNS server so mesh names
	// resolve for every app, restoring it on shutdown (Linux).
	ManageResolv bool
	// DisableDisco skips the standalone disco responder. Required with the real
	// kernel-WireGuard data plane, which owns the ListenPort itself (a separate
	// UDP socket on the same port would collide). Hole-punch path discovery over
	// the WG socket is a later refinement.
	DisableDisco bool
	// SplitTunnel, if set, is the routing engine that decides which destinations
	// bypass the exit (direct) or are blocked while an exit is active (§8.4).
	SplitTunnel *routing.Engine
	// VerifyKey, if set, is the key authority's public key. Peers whose signature
	// does not verify are dropped, so a compromised coord cannot inject a peer
	// with a swapped WireGuard key (DESIGN.md §5).
	VerifyKey   ed25519.PublicKey
	VerifyPQKey *mldsa65.PublicKey
	// RequirePQC drops peers until an authenticated ML-KEM-768 session supplies
	// a WireGuard PSK. Production desktop and mobile clients enable this.
	RequirePQC bool
	// TunnelDNS is the resolver used while an exit is active, to prevent DNS
	// leaks (e.g. a DoH endpoint reachable only through the tunnel). Empty keeps
	// the system resolver.
	TunnelDNS string
	// RelayAddr is an ratelmesh-relay to use as the fallback WireGuard transport for
	// peers with no direct path (DESIGN.md §3.2). Empty disables relay fallback.
	RelayAddr string
	// ForceRelay routes ALL peer traffic through the relay instead of only as a
	// fallback — useful where direct connectivity is impossible or undesirable
	// (e.g. hard NAT, or an always-relay privacy posture).
	ForceRelay bool
	// EnableDiscoProbe turns on the out-of-band disco reachability probe used to
	// gate relay→direct upgrade (docs/relay-upgrade-probe.md). Off by default and
	// still being built up sub-step by sub-step; enabling it only advertises local
	// disco endpoints for now (no consumer yet).
	EnableDiscoProbe bool
	// CoordTransport, if set (e.g. "wss"), carries the control-plane HTTP
	// connection inside a censorship-resistant camouflage transport instead of
	// plain HTTPS, so a client on a network that throttles TLS to the
	// coordinator's CDN host can still register. Empty keeps plain HTTPS — no
	// behavior change for uncensored clients. CoordFrontDoor is the "host:port"
	// the transport actually dials (the CDN edge / front door); it defaults to the
	// coordinator host:443 when empty. See internal/control/camotransport.go.
	CoordTransport string
	CoordFrontDoor string
	// RemoteServiceDetector probes only target-local, explicitly allowlisted
	// listeners when the Tenant policy enables remote access for this device.
	// Nil uses the bounded standard detector.
	RemoteServiceDetector RemoteServiceDetector
	// RemoteAccessCandidates overrides the fixed platform defaults. Nil selects
	// SSH/RDP/VNC standard ports; an explicit empty slice advertises none.
	RemoteAccessCandidates []remoteaccess.Candidate
	// RemoteAccessPolicyStore persists the highest authority-signed remote
	// access policy accepted by this device. Nil creates a private file-backed
	// store in StateDir when VerifyKey is configured.
	RemoteAccessPolicyStore remoteaccess.PolicyFloorStore
	Engine                  wgengine.Engine
	Enforcer                netguard.Enforcer
	Logger                  *slog.Logger
}

// Daemon is the long-running client: it maintains the control-plane connection,
// keeps the data plane in sync with the latest netmap, and serves local status.
type Daemon struct {
	cfg    Config
	log    *slog.Logger
	client *control.Client

	doctorOnce sync.Once
	doctor     *NetworkDoctor
	engine     wgengine.Engine
	// applyMu serializes prepare/apply/commit so a poll, relay callback and local
	// API request cannot interleave candidate state while programming the engine.
	applyMu sync.Mutex

	mu                 sync.Mutex
	state              BackendState
	nodeID             string
	priv               types.Key
	machineIdentity    string
	pqKeys             *pqcrypto.DeviceKeys
	pqSecrets          map[string]pqSecretRecord
	status             Status
	preferredExit      string       // peer name or mesh IP of the chosen exit ("" = none)
	internetFallback   bool         // fail open to physical internet if the exit/data plane fails
	locationRegion     string       // authorized system location, already reduced to a coarse region
	lastNetmap         types.Netmap // last applied map, for re-applying on exit change
	bootstrapNetmap    types.Netmap // authenticated LKG restored before control reconnect
	exitPeerKey        types.Key    // selected exit whose readiness exitRouted describes
	exitRouted         bool         // true only while default routes are installed
	exitHandshakeAfter time.Time    // path changes require a handshake newer than this
	exitTrafficAfter   time.Time    // receive progress must be newer to prove EXIT traffic

	disco    *magicsock.DiscoResponder
	paths    map[types.Key]*magicsock.PeerPath // per-peer direct/relay path state
	pathType map[types.Key]string              // peer key -> "direct"/"relay"/"-"
	probing  map[types.Key]bool                // exact-socket candidate race currently running
	// candidateIndex/attempts drive a platform-neutral fallback for kernel
	// WireGuard engines whose live UDP socket cannot be borrowed for an active
	// probe. The selected candidate is advanced only from real WireGuard liveness,
	// never from a device name, address literal or assumed home subnet.
	candidateIndex    map[types.Key]int
	candidateAttempts map[types.Key]int
	guard             netguard.Enforcer // kill-switch firewall enforcer
	zone              *dns.Zone         // MagicDNS name->mesh IP (§3.1)
	remotePolicyStore remoteaccess.PolicyFloorStore
	remoteAccess      remoteAccessView
	// remotePlatform is derived from the local executable's GOOS, never from
	// coordinator-supplied Netmap metadata. It anchors managed firewall ports.
	remotePlatform   remoteaccess.Platform
	remoteExpiry     time.Time
	remoteExpiryWake chan struct{}

	dnsServer        *dns.Server // running MagicDNS server (nil if not enabled)
	dnsSystemUpstrms []string    // resolvers to use when no exit is active
	systemResolver   dns.SystemResolver
	dnsModeKnown     bool
	dnsTunnelMode    bool

	relayClient            *relay.Client           // connection to the fallback relay (nil if none)
	bridge                 *magicsock.RelayBridge  // relay-as-WireGuard-transport (nil if none)
	relayAddr              netip.AddrPort          // connected relay's addr (kill-switch TCP allow)
	relaySpecs             []string                // effective relay list (flag or DERPMap), for reconnect
	relaySpec              string                  // the spec of the currently-connected relay (rotation)
	relayDialing           bool                    // a connect is in flight (serializes ensureRelay)
	runCtx                 context.Context         // lifetime of Run, for lazily-created bridge sockets
	relayed                map[types.Key]bool      // peers currently routed over the relay (fallback)
	directSince            map[types.Key]time.Time // when each peer was last (re)programmed on direct
	relaySince             map[types.Key]time.Time // when each peer was switched to the relay
	epSeen                 map[types.Key]string    // last advertised endpoints per peer (detect change)
	lastRx                 map[types.Key]int64     // last observed rx-bytes per peer (liveness)
	rxProgress             map[types.Key]time.Time // when rx last increased per peer (liveness)
	lastTx                 map[types.Key]int64     // last observed tx-bytes per peer
	unansweredTx           map[types.Key]int64     // traffic sent since the last receive progress
	txDemandSince          map[types.Key]time.Time // start of the current unanswered traffic window
	lastSilentPathRecovery time.Time               // rate-limits macOS socket rebuilds
	// consecutive `wg show` failures observed by relaySwitchLoop; guarded by mu.
	dataPlaneFailures         int
	networkRecoveryInProgress bool
	controlRecovered          bool // registration succeeded since the previous retry

	relayDNSMu    sync.Mutex
	relayDNSCache map[string]relayDNSEntry // relay hostname spec -> resolved IPs (TTL)

	natMu      sync.Mutex
	exitNAT    exitstack.NAT
	natEnabled bool

	discoReflexive netip.AddrPort        // STUN'd reflexive addr of the disco socket (NAT mapping)
	wgReflexive    netip.AddrPort        // last valid mapping of the persistent WireGuard socket
	portMapping    magicsock.PortMapping // PCP/NAT-PMP mapping on the physical gateway
}

// relayDNSEntry caches a relay hostname's resolved endpoints until expiry.
type relayDNSEntry struct {
	addrs  []netip.AddrPort
	expiry time.Time
}

// relayDNSTTL bounds how long a resolved relay hostname is reused for the
// kill-switch allow-list before re-resolving. relayDNSRetryTTL is the shorter
// window used after a failed lookup (keep serving last-known-good, retry sooner).
const (
	relayDNSTTL      = 5 * time.Minute
	relayDNSRetryTTL = 30 * time.Second
)

// New builds a daemon from config, loading or creating the device identity.
func New(cfg Config) (*Daemon, error) {
	coordURL, err := url.Parse(cfg.CoordURL)
	if err != nil || coordURL.Host == "" || (coordURL.Scheme != "http" && coordURL.Scheme != "https") {
		return nil, fmt.Errorf("invalid coord URL %q: expected http(s)://host", cfg.CoordURL)
	}
	if cfg.StateDir == "" {
		return nil, errors.New("state directory is required")
	}
	if cfg.Role == "" {
		cfg.Role = types.RolePlain
	}
	switch cfg.Role {
	case types.RolePlain, types.RoleExit, types.RoleSubnetRouter:
	default:
		return nil, fmt.Errorf("invalid node role %q", cfg.Role)
	}
	if err := validateRoleConfig(cfg, runtime.GOOS); err != nil {
		return nil, err
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Engine == nil {
		cfg.Engine = wgengine.NewStub(cfg.Logger)
	}
	if cfg.Enforcer == nil {
		cfg.Enforcer = netguard.NewStubEnforcer(cfg.Logger)
	}
	st, err := loadOrCreateState(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = deviceListenPort(st.PrivateKey.Public())
	}
	pqKeys, err := pqcrypto.LoadOrCreateDeviceKeys(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	pqSecrets, err := loadPQSecrets(cfg.StateDir, st.PrivateKey)
	if err != nil {
		return nil, err
	}
	machineIdentity, err := loadMachineIdentity(cfg.StateDir, st.PrivateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("load physical machine identity: %w", err)
	}
	cleanupPending, err := cleanupPendingState(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("read cleanup state: %w", err)
	}
	remotePolicyStore := cfg.RemoteAccessPolicyStore
	if remotePolicyStore == nil && len(cfg.VerifyKey) > 0 {
		remotePolicyStore, err = remoteaccess.NewFilePolicyFloorStore(cfg.StateDir, "remote-access-policy.json")
		if err != nil {
			return nil, fmt.Errorf("open remote access policy floor: %w", err)
		}
	}
	var bootstrapNetmap types.Netmap
	if cached, err := loadCachedNetmap(cfg.StateDir, cfg.CoordURL, st.PrivateKey, cfg.Role); err == nil {
		bootstrapNetmap = cached
	} else if !errors.Is(err, os.ErrNotExist) {
		cfg.Logger.Warn("ignoring invalid last-known-good netmap", "err", err)
	}
	d := &Daemon{
		cfg:               cfg,
		log:               cfg.Logger,
		client:            newCoordClient(cfg),
		engine:            cfg.Engine,
		state:             StateStopped,
		nodeID:            st.NodeID,
		priv:              st.PrivateKey,
		machineIdentity:   machineIdentity,
		pqKeys:            pqKeys,
		pqSecrets:         pqSecrets,
		preferredExit:     st.PreferredExit,
		internetFallback:  st.InternetFallback,
		bootstrapNetmap:   bootstrapNetmap,
		paths:             make(map[types.Key]*magicsock.PeerPath),
		pathType:          make(map[types.Key]string),
		probing:           make(map[types.Key]bool),
		candidateIndex:    make(map[types.Key]int),
		candidateAttempts: make(map[types.Key]int),
		guard:             cfg.Enforcer,
		zone:              dns.NewZone(""),
		remotePolicyStore: remotePolicyStore,
		remoteExpiryWake:  make(chan struct{}, 1),
		relayed:           make(map[types.Key]bool),
		directSince:       make(map[types.Key]time.Time),
		relaySince:        make(map[types.Key]time.Time),
		epSeen:            make(map[types.Key]string),
		lastRx:            make(map[types.Key]int64),
		rxProgress:        make(map[types.Key]time.Time),
		lastTx:            make(map[types.Key]int64),
		unansweredTx:      make(map[types.Key]int64),
		txDemandSince:     make(map[types.Key]time.Time),
	}
	if platform, ok := remoteAccessPlatformForGOOS(runtime.GOOS); ok {
		d.remotePlatform = platform
	}
	d.client.SetNodeKey(st.PrivateKey)
	d.client.SetMachineIdentity(machineIdentity)
	d.client.SetToken(st.SessionToken) // prove node ownership across restarts (§1)
	d.status = Status{
		State:              StateStopped,
		CoordURL:           cfg.CoordURL,
		InternetFallback:   st.InternetFallback,
		EnrollmentRequired: enrollmentRequired(st.NodeID, st.SessionToken, cfg.AuthKey),
		CleanupPending:     cleanupPending,
	}
	return d, nil
}

// validateRoleConfig rejects flag combinations at construction time that would
// otherwise be accepted here but fail (or silently do nothing) deep in the
// data plane later. goos is a parameter so the Windows rules are testable on
// any development host.
func validateRoleConfig(cfg Config, goos string) error {
	// EnableNAT is permission to activate NAT when the server-authoritative
	// netmap grants Exit. It is intentionally valid for a locally plain member so
	// a Tenant administrator can enable or disable Exit without editing flags.
	if len(cfg.AdvertiseRoutes) > 0 && cfg.Role != types.RoleSubnetRouter {
		return errors.New("advertise-routes requires the subnet-router role")
	}
	// The Windows engine implements the kill switch by keeping /0 AllowedIPs so
	// the official tunnel service arms its fail-closed firewall — which cannot
	// coexist with split-tunnel direct bypass routes. Reject the combination
	// here; otherwise it only surfaces when an exit is activated, leaving the
	// user with a data plane that silently never comes up.
	if goos == "windows" && cfg.KillSwitch && cfg.SplitTunnel != nil && len(cfg.SplitTunnel.DirectPrefixes()) > 0 {
		return errors.New("on Windows, kill-switch cannot be combined with split-tunnel direct rules (the WireGuard /0 kill switch bypasses no routes)")
	}
	if cfg.RemoteAccessCandidates != nil {
		platform, ok := remoteAccessPlatformForGOOS(goos)
		if !ok {
			if len(cfg.RemoteAccessCandidates) != 0 {
				return errors.New("remote-access services are unsupported on this platform")
			}
		} else if _, err := remoteTargetCandidatePorts(cfg.RemoteAccessCandidates, platform); err != nil {
			return fmt.Errorf("invalid remote-access candidates: %w", err)
		}
	}
	return nil
}

// PublicKey returns this device's WireGuard public key.
func (d *Daemon) PublicKey() types.Key { return d.priv.Public() }

// Run brings the daemon up and blocks until ctx is cancelled, maintaining the
// registration + long-poll loop with reconnect/backoff.
func (d *Daemon) Run(ctx context.Context) (runErr error) {
	d.mu.Lock()
	d.runCtx = ctx
	d.mu.Unlock()
	d.setState(StateStarting)
	// Kernel WireGuard on Linux/Windows cannot lend us its live UDP socket for
	// STUN. Probe from the final listen port immediately before engine startup;
	// the kernel interface then reuses that stable source port. Native mobile
	// providers may supply an even better candidate through ExtraEndpoints.
	if _, exactSocketSTUN := d.engine.(wgengine.PublicEndpointDiscoverer); !exactSocketSTUN && len(d.cfg.ExtraEndpoints) == 0 && d.cfg.STUNAddr != "" {
		discoverCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		reflexive, err := magicsock.DiscoverReflexiveFromPort(discoverCtx, d.cfg.ListenPort, d.cfg.STUNAddr)
		cancel()
		if err == nil && reflexive.IsValid() {
			d.mu.Lock()
			d.wgReflexive = reflexive
			d.mu.Unlock()
			d.log.Info("startup reflexive endpoint discovered", "addr", reflexive)
		} else if err != nil {
			d.log.Debug("startup STUN discovery failed", "err", err)
		}
	}
	// Write the cleanup intent before the first data-plane mutation. A SIGKILL,
	// power loss, or process crash after Up/route/firewall changes therefore
	// leaves a durable instruction for the next launch instead of an
	// unobservable half-installed network plan.
	if err := persistCleanupPending(d.cfg.StateDir); err != nil {
		return fmt.Errorf("persist write-ahead cleanup intent: %w", err)
	}
	d.mu.Lock()
	d.status.CleanupPending = true
	d.mu.Unlock()
	if preparer, ok := d.engine.(wgengine.PersistentCleanupPreparer); ok {
		if err := preparer.PreparePersistentCleanup(d.cfg.StateDir); err != nil {
			return fmt.Errorf("reconcile persistent data-plane cleanup: %w", err)
		}
	}
	defer func() {
		var cleanupErr error
		if err := d.engine.Down(); err != nil {
			cleanupErr = fmt.Errorf("data-plane teardown incomplete: %w", err)
			// Keep the managed firewall armed. Clearing a kill switch while
			// routes or the tunnel may still be present would turn an
			// incomplete teardown into a traffic-leak window.
			d.log.Error("data-plane teardown incomplete; retaining managed firewall", "err", err)
		} else if err := d.guard.Clear(); err != nil {
			cleanupErr = fmt.Errorf("managed firewall teardown incomplete: %w", err)
			d.log.Error("managed firewall teardown incomplete", "err", err)
		}
		if cleanupErr != nil {
			d.mu.Lock()
			d.status.CleanupPending = true
			d.mu.Unlock()
			runErr = errors.Join(runErr, cleanupErr)
			return
		}
		if err := clearCleanupPending(d.cfg.StateDir); err != nil {
			d.mu.Lock()
			d.status.CleanupPending = true
			d.mu.Unlock()
			runErr = errors.Join(runErr, fmt.Errorf("clear cleanup state: %w", err))
			return
		}
		d.mu.Lock()
		d.status.CleanupPending = false
		d.mu.Unlock()
	}()
	if err := d.engine.Up(); err != nil {
		return err
	}
	go d.networkPathLoop(ctx)
	// Open the persistent WireGuard UDP socket before registration so STUN sees
	// the mapping peers will actually use. Without this ordering, macOS registers
	// only private candidates and remote mobile peers have no endpoint to punch.
	if preparer, ok := d.engine.(wgengine.EndpointDiscoveryPreparer); ok {
		if err := preparer.PrepareEndpointDiscovery(wgengine.Config{
			PrivateKey: d.priv,
			ListenPort: d.cfg.ListenPort,
		}); err != nil {
			d.log.Warn("prepare endpoint discovery failed", "err", err)
		}
	}
	// Ask the physical gateway for an explicit mapping before registration. This
	// is best-effort: unsupported routers continue with STUN/IPv6 candidates.
	mapCtx, mapCancel := context.WithTimeout(ctx, 6*time.Second)
	d.refreshPortMapping(mapCtx)
	mapCancel()
	go d.portMappingLoop(ctx)
	remoteExpiryCtx, stopRemoteExpiry := context.WithCancel(ctx)
	remoteExpiryDone := make(chan struct{})
	go func() {
		defer close(remoteExpiryDone)
		d.remoteTargetExpiryLoop(remoteExpiryCtx)
	}()
	defer func() {
		stopRemoteExpiry()
		<-remoteExpiryDone
	}()

	// Best-effort disco responder for hole-punching. Skipped when the real WG
	// data plane owns the ListenPort. If the port is taken (e.g. two stub daemons
	// on one host in tests), we simply stay on the relay path.
	if d.cfg.DisableDisco {
		d.log.Debug("disco responder disabled (real data plane owns the WG port)")
	} else if resp, err := magicsock.ListenDisco(fmt.Sprintf(":%d", d.cfg.ListenPort)); err == nil {
		d.mu.Lock()
		d.disco = resp
		d.mu.Unlock()
		go resp.Serve(ctx)
		defer resp.Close()
	} else {
		d.log.Debug("disco responder not started", "err", err)
	}

	// Out-of-band disco responder on the disco port (ListenPort+1), for the
	// relay→direct upgrade probe. Off unless -disco-probe; separate from the
	// WG-port responder above (which is off under wgreal).
	if resp, err := d.startDiscoResponder(ctx); err != nil {
		d.log.Warn("disco probe responder failed to start", "err", err)
	} else if resp != nil {
		d.log.Info("disco probe responder listening", "addr", resp.LocalAddr())
		defer resp.Close()
	}

	// Exit node NAT is armed after the first netmap has configured the tunnel.
	// This ordering is required on Windows, where the WireGuard service creates
	// the adapter during Reconfigure rather than Up.
	if d.cfg.EnableNAT {
		d.exitNAT = exitstack.New(true, d.log)
		defer d.disableExitNAT()
	}

	// MagicDNS server for peer name resolution (+ optional resolv.conf takeover).
	if d.cfg.DNSAddr != "" {
		upstreams := d.cfg.DNSUpstreams
		var resolv dns.SystemResolver
		if d.cfg.ManageResolv {
			resolv = dns.NewSystemResolver()
			if len(upstreams) == 0 {
				upstreams = resolv.CurrentUpstreams()
			}
		}
		if srv, err := dns.NewServer(d.zone, d.cfg.DNSAddr, upstreams...); err != nil {
			d.log.Error("dns server start failed", "err", err)
		} else {
			d.log.Info("MagicDNS server listening", "addr", srv.LocalAddr().String(), "upstreams", len(upstreams))
			d.mu.Lock()
			d.dnsServer = srv
			d.dnsSystemUpstrms = append([]string(nil), upstreams...)
			d.mu.Unlock()
			go srv.Serve(ctx)
			defer srv.Close()
			if resolv != nil {
				if host, _, e := net.SplitHostPort(d.cfg.DNSAddr); e == nil {
					if err := resolv.Install(host); err != nil {
						d.log.Error("resolv.conf takeover failed", "err", err)
					} else {
						d.log.Info("resolv.conf now points at MagicDNS", "server", host)
						d.mu.Lock()
						d.systemResolver = resolv
						d.mu.Unlock()
						defer func() {
							if err := resolv.Restore(); err != nil {
								d.log.Warn("system resolver restore failed", "err", err)
							}
							d.mu.Lock()
							d.systemResolver = nil
							d.mu.Unlock()
						}()
					}
				}
			}
		}
	}

	// Relay fallback transport: connect now if a relay was given on the command
	// line; otherwise it is connected lazily from the coord-advertised DERPMap
	// once the first netmap arrives (DESIGN.md §3.2). The switch loop runs for the
	// whole session (it no-ops until a relay is connected) so it survives relay
	// reconnects without spawning duplicates.
	go d.relaySwitchLoop(ctx)
	go d.relayReconnectLoop(ctx) // keep the relay connected across drops (§2)
	go d.directProbeLoop(ctx)
	if d.cfg.RelayAddr != "" {
		d.mu.Lock()
		d.relaySpecs = []string{d.cfg.RelayAddr}
		d.mu.Unlock()
		d.ensureRelay(ctx, []string{d.cfg.RelayAddr})
	}
	defer d.closeRelay()

	// Restore the authenticated last-known-good map before making the first
	// coordinator request. A control-plane outage therefore does not turn a
	// reboot into a data-plane outage: routes, peers, DNS, relay and exit state
	// come back from local durable state, then control synchronization retries in
	// the background.
	d.mu.Lock()
	bootstrap := d.bootstrapNetmap
	d.bootstrapNetmap = types.Netmap{}
	d.mu.Unlock()
	if bootstrap.Version > 0 {
		if err := d.applyNetmap(bootstrap); err != nil {
			d.log.Error("last-known-good netmap restore failed", "version", bootstrap.Version, "err", err)
		} else {
			d.setState(StateRunning)
			d.log.Info("restored data plane from last-known-good netmap", "version", bootstrap.Version, "peers", len(bootstrap.Peers))
		}
	}

	backoff := time.Second
	for ctx.Err() == nil {
		if err := d.session(ctx); err != nil {
			if ctx.Err() != nil {
				break
			}
			if d.consumeControlRecovered() {
				backoff = time.Second
			}
			d.client.ResetNetwork()
			d.log.Warn("control session ended, retrying", "err", err, "backoff", backoff)
			d.markControlRetrying()
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
	d.setState(StateStopped)
	return ctx.Err()
}

// session registers then long-polls until an error or ctx cancellation.
func (d *Daemon) session(ctx context.Context) error {
	platform, locationRegion := d.deviceMetadata()
	regResp, err := d.client.Register(ctx, types.RegisterRequest{
		NodeKey:            d.priv.Public(),
		PQKEMPublicKey:     d.pqKeys.KEMPublicKey(),
		PQSigningPublicKey: d.pqKeys.MLDSAPublicKey(),
		Hostname:           d.cfg.Hostname,
		MachineIdentity:    d.machineIdentity,
		Platform:           platform,
		LocationRegion:     locationRegion,
		Endpoints:          d.localEndpoints(),
		DiscoEndpoints:     d.discoEndpoints(),
		Role:               d.cfg.Role,
		AdvertiseRoutes:    d.cfg.AdvertiseRoutes,
		Tags:               d.cfg.Tags,
	})
	if err != nil {
		if enrollmentInvalidated(err) {
			// Re-arm the prompt: the stored credentials are no longer accepted, so
			// the user has to enroll again. Transient failures leave it untouched.
			d.mu.Lock()
			d.status.EnrollmentRequired = true
			d.mu.Unlock()
		}
		return err
	}
	d.mu.Lock()
	d.nodeID = regResp.NodeID
	d.status.EnrollmentRequired = false
	d.mu.Unlock()
	if err := saveNodeID(d.cfg.StateDir, regResp.NodeID); err != nil {
		d.log.Warn("persist node ID failed", "err", err)
	}
	if err := saveSessionToken(d.cfg.StateDir, d.client.Token()); err != nil {
		d.log.Warn("persist session token failed", "err", err)
	}
	if err := d.ensurePQSessions(ctx, regResp.Netmap); err != nil {
		return err
	}

	if err := d.applyNetmap(regResp.Netmap); err != nil {
		return fmt.Errorf("apply initial netmap: %w", err)
	}
	d.markControlRecovered()
	d.setState(StateRunning)
	status := d.Status()
	d.log.Info("mesh up", "node", regResp.NodeID, "ip", status.Self.MeshIP,
		"peers", len(regResp.Netmap.Peers))

	version := regResp.Netmap.Version
	lastToken := d.client.Token()
	for {
		platform, locationRegion = d.deviceMetadata()
		selectedExitID, activeExitID := d.reportedExitUsage()
		remoteServices, advertiseServices := d.detectRemoteServices(ctx, regResp.NodeID, platform)
		if !advertiseServices {
			remoteServices = nil
		}
		resp, err := d.client.PollWithRuntimeAndServices(ctx, regResp.NodeID, version, d.localEndpoints(), d.discoEndpoints(), platform, locationRegion, selectedExitID, activeExitID, remoteServices)
		if err != nil {
			return err
		}
		// Persist the refreshed session token when it changes (§3 renewal).
		if tok := d.client.Token(); tok != lastToken {
			if err := saveSessionToken(d.cfg.StateDir, tok); err != nil {
				d.log.Warn("persist refreshed session token failed", "err", err)
			}
			lastToken = tok
		}
		if resp.Changed {
			if err := d.ensurePQSessions(ctx, resp.Netmap); err != nil {
				return err
			}
			if err := d.applyNetmap(resp.Netmap); err != nil {
				d.log.Error("apply netmap failed", "err", err)
				continue
			}
			version = resp.Netmap.Version
			d.log.Info("netmap updated", "version", version, "peers", len(resp.Netmap.Peers))
		}
	}
}

func (d *Daemon) markControlRecovered() {
	d.mu.Lock()
	d.controlRecovered = true
	d.mu.Unlock()
}

func (d *Daemon) consumeControlRecovered() bool {
	d.mu.Lock()
	recovered := d.controlRecovered
	d.controlRecovered = false
	d.mu.Unlock()
	return recovered
}

func (d *Daemon) reportedExitUsage() (selectedID, activeID string) {
	d.mu.Lock()
	preferred := d.preferredExit
	activeKey := d.exitPeerKey
	active := d.exitRouted && d.status.ExitTrafficVerified
	peers := append([]types.Node(nil), d.lastNetmap.Peers...)
	d.mu.Unlock()
	for _, peer := range peers {
		if peer.Role != types.RoleExit || !peerMatches(peer, preferred) {
			continue
		}
		selectedID = peer.ID
		if active && peer.Key == activeKey {
			activeID = peer.ID
		}
		return selectedID, activeID
	}
	return "", ""
}

func (d *Daemon) deviceMetadata() (string, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	platform := runtime.GOOS
	if platform == "darwin" {
		platform = "macos"
	}
	return platform, d.locationRegion
}

// SetSystemLocation accepts coordinates only from a platform location service
// after native authorization. It immediately discards them after reducing them
// to a coarse region for the next control-plane heartbeat.
func (d *Daemon) SetSystemLocation(latitude, longitude float64) error {
	region := georegion.FromCoordinates(latitude, longitude)
	if region == "" {
		return errors.New("invalid system location")
	}
	d.mu.Lock()
	d.locationRegion = region
	d.mu.Unlock()
	return nil
}

// applyNetmap translates a netmap into a data-plane config and updates status.
// If an exit node is selected, only that exit is programmed with the default
// route (0.0.0.0/0, ::/0); other exit nodes are demoted to their mesh address
// only, so traffic egresses solely through the chosen exit (DESIGN.md §3.3).
func (d *Daemon) applyNetmap(nm types.Netmap) error {
	d.applyMu.Lock()
	reapply, err := d.applyNetmapLocked(nm)
	d.applyMu.Unlock()
	if err != nil {
		return err
	}
	if reapply {
		// Relay rotation changes each bridge-local UDP endpoint. Re-render once
		// after the committed rotation so WireGuard follows the replacement.
		if err := d.applyNetmap(nm); err != nil {
			d.log.Error("relay rotation reapply failed", "err", err)
		}
	}
	return nil
}

func (d *Daemon) applyNetmapLocked(nm types.Netmap) (bool, error) {
	if err := d.validateSelfIdentity(nm.Self); err != nil {
		return false, err
	}
	d.mu.Lock()
	preferred := d.preferredExit
	ctx := d.runCtx
	priorNetmap := d.lastNetmap
	priorExitKey := d.exitPeerKey
	priorExitRouted := d.exitRouted
	trafficAfter := d.exitTrafficAfter
	trafficVerified := d.status.ExitTrafficVerified
	d.mu.Unlock()
	if priorNetmap.Version > 0 {
		if nm.Version < priorNetmap.Version {
			return false, fmt.Errorf("%w: got %d after %d", ErrNetmapRollback, nm.Version, priorNetmap.Version)
		}
		if nm.Version == priorNetmap.Version && !reflect.DeepEqual(nm, priorNetmap) {
			return false, fmt.Errorf("%w: version %d", ErrNetmapEquivocation, nm.Version)
		}
	}
	remoteNow := time.Now()
	remoteView := d.authenticateRemoteAccessNetmap(nm, remoteNow)
	var remoteTarget remoteTargetPolicy
	if d.remoteFirewallCapable() &&
		(len(nm.RemoteAccessPolicyState.Payload) != 0 || d.guard.Current().RemoteEnforcement) {
		var targetErr error
		remoteTarget, targetErr = d.deriveRemoteTargetPolicy(nm, remoteNow)
		if targetErr != nil {
			// The returned policy is deliberately fail-closed. Keep applying
			// the Mesh itself, but never keep an old allow rule on this error.
			d.log.Warn("remote target policy rejected; applying closed boundary", "err", targetErr)
		}
	}
	// Revoke the previously presented launchers before any fallible data-plane
	// work. A newly accepted policy/grant view is committed only after the
	// engine, routes and firewall accept the netmap, but a revocation must not
	// remain hidden behind an unrelated reconfiguration failure.
	d.mu.Lock()
	d.remoteAccess = remoteAccessView{services: make(map[remoteTargetKey][]remoteAuthorizedService)}
	d.status.Self.RemoteAccessAllowed = false
	d.status.Self.RemoteServices = nil
	for i := range d.status.Peers {
		d.status.Peers[i].RemoteAccessAllowed = false
		d.status.Peers[i].RemoteServices = nil
	}
	d.mu.Unlock()

	// Record the effective relay list (flag pin, else coord DERPMap) for the
	// reconnect loop. If the currently-connected relay is no longer advertised
	// (revoked / rotated), drop it so we reconnect to a current one — otherwise a
	// removed relay would keep serving traffic (security review §2). ensureRelay
	// is a no-op when already connected (DESIGN.md §3.2).
	relays := nm.Relays
	if d.cfg.RelayAddr != "" {
		relays = []string{d.cfg.RelayAddr}
	}
	d.mu.Lock()
	priorBridge := d.bridge
	rotateRelay := priorBridge != nil && d.relaySpec != "" && !containsStr(relays, d.relaySpec)
	d.mu.Unlock()
	connectedForCandidate := false
	if priorBridge == nil && ctx != nil && len(relays) > 0 {
		connectedForCandidate = d.ensureRelay(ctx, relays)
	}
	rollbackCandidateState := func() {
		if connectedForCandidate {
			d.mu.Lock()
			var candidate *magicsock.RelayBridge
			var candidateClient *relay.Client
			if d.bridge != nil && d.bridge != priorBridge {
				candidate, candidateClient = d.clearBridgeLocked()
			}
			d.mu.Unlock()
			closeRelayResources(candidate, candidateClient)
		}
		if priorBridge != nil {
			keep := make([]types.Key, 0, len(priorNetmap.Peers))
			for _, p := range priorNetmap.Peers {
				keep = append(keep, p.Key)
			}
			priorBridge.RetainPeers(keep)
		}
	}

	selectedExit := ""
	var activeExitKey types.Key
	exitRouted := false
	var activeExitEndpoints []string
	cfg := wgengine.Config{
		PrivateKey: d.priv,
		ListenPort: d.cfg.ListenPort,
		Addresses:  meshAddrsAsPrefixes(nm.Self.MeshIPs),
	}
	// The wg-quick renderer used by WireGuard for Windows installs this resolver
	// on the tunnel adapter. Unix engines ignore the quick-only DNS directive and
	// continue to use their native resolv.conf/networksetup managers.
	if d.cfg.ManageResolv {
		if host, _, err := net.SplitHostPort(d.cfg.DNSAddr); err == nil {
			if server, err := netip.ParseAddr(host); err == nil {
				cfg.DNSServers = []netip.Addr{server}
			}
		}
	}
	type peerCandidate struct {
		key      types.Key
		epKey    string
		changed  bool
		viaRelay bool
	}
	peerCandidates := make([]peerCandidate, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		p.Endpoints = safePeerEndpoints(p.Endpoints)
		// epKey describes only coordinator-advertised state. Locally reordering
		// candidates must not masquerade as a peer roam and reset the path trial on
		// every apply.
		epKey := strings.Join(p.Endpoints, "\x00")
		// When both nodes have the same reflexive public address they are behind
		// the same edge NAT. Prefer the peer's private candidate in that case:
		// sending to its public mapping depends on NAT hairpin support, while a
		// routed LAN/private path works without any router port-forwarding.
		p.Endpoints = preferSameNATPrivateEndpoints(nm.Self.Endpoints, p.Endpoints)
		p.Endpoints = d.preferCandidateEndpoint(p.Key, p.Endpoints)
		p.Endpoints = d.preferConfirmedEndpoint(p.Key, p.Endpoints)
		presharedKey, pqReady := d.pqPresharedKey(nm, p)
		if !pqReady {
			d.log.Warn("dropping peer: post-quantum session missing or invalid", "name", p.Name, "key", p.Key.ShortString())
			continue
		}
		legacyUnsignedRoutes := false
		// Key-authority check: drop peers whose credential does not verify, so a
		// compromised coord cannot MITM by swapping a peer's WireGuard key (§5).
		if d.cfg.VerifyKey != nil {
			// RouteSig was added after the identity credential. During a rolling
			// coordinator-first upgrade an older persisted node may legitimately
			// have no route signature yet; retain identity verification for that
			// migration case. Once RouteSig is present it is mandatory and may not
			// be stripped or altered without dropping the peer.
			badRouteSig := len(p.RouteSig) > 0 && !sign.VerifyRoutes(d.cfg.VerifyKey, p, p.RouteSig)
			badCapabilitySig := (p.Capabilities.Exit || p.Capabilities.Relay) &&
				!sign.VerifyCapabilities(d.cfg.VerifyKey, p, p.CapabilitySig)
			if !sign.Verify(d.cfg.VerifyKey, p, p.Sig) || badRouteSig || badCapabilitySig {
				d.log.Warn("dropping peer: bad authority or route signature", "name", p.Name, "key", p.Key.ShortString())
				continue
			}
			legacyUnsignedRoutes = len(p.RouteSig) == 0
		}
		if d.cfg.VerifyPQKey != nil {
			badCapabilitySig := (p.Capabilities.Exit || p.Capabilities.Relay) &&
				!sign.VerifyCapabilitiesPQ(d.cfg.VerifyPQKey, p, p.PQCapabilitySig)
			if !sign.VerifyPQ(d.cfg.VerifyPQKey, p, p.PQSig) ||
				!sign.VerifyRoutesPQ(d.cfg.VerifyPQKey, p, p.PQRouteSig) || badCapabilitySig {
				d.log.Warn("dropping peer: bad ML-DSA authority or route signature", "name", p.Name, "key", p.Key.ShortString())
				continue
			}
		}
		allowed := wgengine.ParseAllowedIPs(p.AllowedIPs)
		if legacyUnsignedRoutes {
			if p.Role == types.RoleExit {
				allowed = keepMeshAndDefaults(allowed, p.MeshIPs)
			} else {
				allowed = keepMeshOnly(allowed, p.MeshIPs)
			}
		}
		if p.Role == types.RoleExit {
			if peerMatches(p, preferred) {
				selectedExit = p.Name
				activeExitKey = p.Key
				activeExitEndpoints = p.Endpoints
				exitRouted = d.exitReadyForPeer(p.Key, time.Now())
				if !exitRouted {
					// Stage the peer and its keepalive first. The real engine promotes
					// the /0 routes only after a recent handshake proves the direct or
					// relay path is usable; otherwise selecting an exit can blackhole
					// the host before relay bootstrap completes.
					allowed = stripDefaultRoutes(allowed)
				}
			} else {
				allowed = stripDefaultRoutes(allowed) // demote unselected exits
			}
		}
		if p.Role == types.RoleSubnetRouter && !d.cfg.AcceptRoutes {
			// Do not route advertised subnets unless the user opted in; keep only
			// the peer's own mesh addresses.
			allowed = keepMeshOnly(allowed, p.MeshIPs)
		}
		// A change in the peer's advertised endpoints (e.g. it roamed) resets the
		// relay-fallback state so the fresh direct path is retried before falling
		// back again.
		d.mu.Lock()
		endpointChanged := d.epSeen[p.Key] != epKey
		relayed := d.relayed[p.Key]
		bridge := d.bridge
		if endpointChanged {
			relayed = false
		}
		d.mu.Unlock()

		endpoints, viaRelay := d.peerEndpointsWith(p, bridge, relayed)
		peerCandidates = append(peerCandidates, peerCandidate{
			key: p.Key, epKey: epKey, changed: endpointChanged, viaRelay: viaRelay,
		})
		cfg.Peers = append(cfg.Peers, wgengine.Peer{
			PublicKey:    p.Key,
			PresharedKey: presharedKey,
			Endpoints:    endpoints,
			AllowedIPs:   allowed,
			Keepalive:    5, // drive handshake attempts so relay fallback is observable
		})
	}
	// Apply split-tunnel overrides only when an exit carries the default route.
	if exitRouted && d.cfg.SplitTunnel != nil {
		cfg.DirectRoutes = d.cfg.SplitTunnel.DirectPrefixes()
		cfg.BlockRoutes = d.cfg.SplitTunnel.BlockPrefixes()
	}
	if exitRouted && selectedExit != "" {
		for _, peer := range cfg.Peers {
			if peer.PublicKey == activeExitKey && hasIPv4DefaultOnly(peer.AllowedIPs) {
				// A v4-only exit must never leave the host's physical IPv6 default
				// usable. /1 blackholes outrank an existing ::/0 on Unix and Windows.
				cfg.BlockRoutes = append(cfg.BlockRoutes, defaultIPv6BlockRoutes()...)
				break
			}
		}
	}
	peerTransportEndpoints := append([]string(nil), activeExitEndpoints...)
	for _, peer := range cfg.Peers {
		peerTransportEndpoints = append(peerTransportEndpoints, peer.Endpoints...)
	}
	peerTransportEndpoints = append(peerTransportEndpoints, d.livePeerEndpoints()...)
	if exitRouted {
		cfg.PhysicalEndpoints = d.exitPhysicalEndpoints(relays)
		// Once /1 routes capture the physical default, every WireGuard peer's
		// encrypted outer transport needs a host-route pin. PF port exceptions
		// alone are insufficient: without these pins an ordinary peer's UDP
		// packets route back into the utun, severing SSH and other Mesh sessions.
		cfg.PhysicalEndpoints = append(cfg.PhysicalEndpoints, physicalTransportAddrs(peerTransportEndpoints)...)
	}
	// Windows' official tunnel service uses this bit to activate its WFP-based
	// fail-closed firewall by preserving /0 routes in the service config.
	d.mu.Lock()
	internetFallback := d.internetFallback
	d.mu.Unlock()
	cfg.KillSwitch = d.cfg.KillSwitch && !internetFallback && exitRouted

	// Arm fail-closed before changing routes. In particular, if either IPv6 /1
	// fails to install, the physical IPv6 default must never become a fallback.
	// Keep it armed while the selected peer is staged/recovering, not only after
	// a fresh handshake has promoted the exit defaults.
	exitSelected := selectedExit != ""
	priorPolicy := d.guard.Current()
	desiredPolicy := d.killSwitchPolicy(exitSelected, peerTransportEndpoints, internetFallback, relays)
	var err error
	desiredPolicy, err = d.composeRemoteTargetPolicy(desiredPolicy, remoteTarget, nm.Self)
	if err != nil {
		// A malformed replacement must not strand a predecessor's temporary
		// allow. Keep its deny boundary and EXIT posture, but remove all grants.
		emergencyClosed := priorPolicy
		emergencyClosed.RemoteAccessRules = nil
		if !reflect.DeepEqual(priorPolicy, emergencyClosed) {
			if closeErr := d.applyKillSwitchPolicy(emergencyClosed); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
		}
		d.setRemoteTargetExpiry(time.Now().Add(time.Second))
		rollbackCandidateState()
		return false, fmt.Errorf("compose managed firewall policy: %w", err)
	}
	// When disarming EXIT protection, preserve the predecessor's output rules
	// until the engine has removed full-tunnel routes. Remote grant revocations
	// are still installed immediately and survive unrelated engine failures.
	deferDisarm := priorPolicy.Enabled && !desiredPolicy.Enabled
	intermediatePolicy := desiredPolicy
	if deferDisarm {
		copyExitPolicy(&intermediatePolicy, priorPolicy)
	}
	firewallApplied := false
	if !reflect.DeepEqual(priorPolicy, intermediatePolicy) {
		if err := d.applyKillSwitchPolicy(intermediatePolicy); err != nil {
			rollbackCandidateState()
			return false, err
		}
		firewallApplied = true
	}
	d.setRemoteTargetExpiry(remoteTarget.NearestExpiry)
	if err := d.engine.Reconfigure(cfg); err != nil {
		if firewallApplied {
			rollbackPolicy := desiredPolicy
			copyExitPolicy(&rollbackPolicy, priorPolicy)
			if !reflect.DeepEqual(d.guard.Current(), rollbackPolicy) {
				if rollbackErr := d.applyKillSwitchPolicy(rollbackPolicy); rollbackErr != nil {
					d.log.Error("managed firewall rollback after data-plane failure failed", "err", rollbackErr)
				}
			}
		}
		rollbackCandidateState()
		return false, err
	}
	if !reflect.DeepEqual(intermediatePolicy, desiredPolicy) {
		if err := d.applyKillSwitchPolicy(desiredPolicy); err != nil {
			// Keep the predecessor's fail-closed policy armed. The engine changed,
			// but cleartext egress remains blocked and the caller can safely retry.
			return false, err
		}
	}
	killOn := desiredPolicy.Enabled
	if nm.Self.Capabilities.Exit || nm.Self.Role == types.RoleExit {
		d.enableExitNAT()
	} else {
		d.disableExitNAT()
	}

	d.updateDNSUpstreams(exitRouted)

	// Commit endpoint/fallback bookkeeping only after the engine accepted the
	// complete candidate. A failed apply must leave the live path decisions intact.
	d.mu.Lock()
	for _, candidate := range peerCandidates {
		if candidate.changed {
			d.epSeen[candidate.key] = candidate.epKey
			delete(d.relayed, candidate.key)
			delete(d.directSince, candidate.key)
			delete(d.relaySince, candidate.key)
			delete(d.lastRx, candidate.key)
			delete(d.rxProgress, candidate.key)
			delete(d.lastTx, candidate.key)
			delete(d.unansweredTx, candidate.key)
			delete(d.txDemandSince, candidate.key)
			delete(d.candidateIndex, candidate.key)
			delete(d.candidateAttempts, candidate.key)
		}
		if candidate.viaRelay {
			d.pathType[candidate.key] = "relay"
		}
	}
	d.relaySpecs = append([]string(nil), relays...)
	bridge := d.bridge
	d.mu.Unlock()

	// Reconcile bridge membership only after commit: RetainPeers closes sockets
	// for removed peers and therefore cannot be part of the prepare phase.
	if bridge != nil {
		keep := make([]types.Key, 0, len(nm.Peers))
		for _, p := range nm.Peers {
			keep = append(keep, p.Key)
		}
		bridge.RetainPeers(keep)
	}

	st := Status{
		State:            StateRunning,
		CoordURL:         d.cfg.CoordURL,
		Version:          nm.Version,
		Self:             peerStatusFromNode(nm.Self),
		SelectedExit:     selectedExit,
		KillSwitch:       killOn,
		InternetFallback: internetFallback,
		DNS:              d.effectiveDNS(exitRouted),
	}
	st.Self.RemoteAccessAllowed = remoteView.selfAllowed
	if !st.Self.RemoteAccessAllowed {
		st.Self.RemoteServices = nil
	}
	remoteStatusNow := time.Now()
	for _, p := range nm.Peers {
		ps := peerStatusFromNode(p)
		ps.RemoteServices = remoteView.servicesFor(p, remoteStatusNow)
		ps.RemoteAccessAllowed = len(ps.RemoteServices) > 0
		if pt := d.currentPathType(p.Key); pt != "" {
			ps.PathType = pt
		}
		if exitRouted && p.Role == types.RoleExit && p.Name == selectedExit {
			ps.PathType = "exit" // marks the active egress in `ratelmesh status`
		}
		st.Peers = append(st.Peers, ps)
		if client, ok := exitClientStatus(nm.Self.ID, p); ok {
			st.ExitClients = append(st.ExitClients, client)
		}
	}
	if exitRouted {
		st.ActiveExit = selectedExit
	}
	if !exitRouted {
		trafficAfter = time.Time{}
		trafficVerified = false
	} else if !priorExitRouted || priorExitKey != activeExitKey {
		// Route activation starts a fresh proof window. Bytes received while this
		// peer was only an ordinary mesh route cannot prove full-tunnel egress.
		trafficAfter = time.Now()
		trafficVerified = false
	}
	st.ExitTrafficVerified = trafficVerified
	d.mu.Lock()
	d.lastNetmap = nm
	d.remoteAccess = remoteView
	d.exitPeerKey = activeExitKey
	d.exitRouted = exitRouted
	d.exitTrafficAfter = trafficAfter
	d.state = StateRunning
	d.status = st
	d.mu.Unlock()

	d.zone.Rebuild(nm.Self, nm.Peers) // MagicDNS records (§3.1)
	d.refreshPaths(nm.Peers)
	if nm.Version > priorNetmap.Version {
		if err := saveCachedNetmap(d.cfg.StateDir, d.cfg.CoordURL, d.priv, d.cfg.Role, nm); err != nil {
			// The live data plane is already committed and may be the user's only
			// connectivity. Never tear it down because durable storage is temporarily
			// unavailable; retain the previous LKG and surface the loss of durability.
			d.log.Warn("persist last-known-good netmap failed", "version", nm.Version, "err", err)
		}
	}

	if rotateRelay {
		d.mu.Lock()
		var rotated *magicsock.RelayBridge
		var rotatedClient *relay.Client
		if d.bridge == priorBridge {
			rotated, rotatedClient = d.clearBridgeLocked()
		}
		d.mu.Unlock()
		if rotated != nil {
			closeRelayResources(rotated, rotatedClient)
			d.log.Info("relay no longer advertised; rotating after netmap commit")
			if ctx != nil && len(relays) > 0 {
				d.ensureRelay(ctx, relays)
			}
			return true, nil
		}
	}
	return false, nil
}

func (d *Daemon) validateSelfIdentity(self types.Node) error {
	d.mu.Lock()
	nodeID := d.nodeID
	d.mu.Unlock()
	if nodeID == "" {
		return nil
	}
	if self.ID != nodeID {
		return fmt.Errorf("%w: self ID %q does not match persisted node ID %q", ErrNetmapIdentity, self.ID, nodeID)
	}
	if self.Key != d.priv.Public() {
		return fmt.Errorf("%w: self key does not match device identity", ErrNetmapIdentity)
	}
	if d.cfg.VerifyKey != nil {
		badRouteSig := len(self.RouteSig) > 0 && !sign.VerifyRoutes(d.cfg.VerifyKey, self, self.RouteSig)
		badCapabilitySig := (self.Capabilities.Exit || self.Capabilities.Relay) &&
			!sign.VerifyCapabilities(d.cfg.VerifyKey, self, self.CapabilitySig)
		if !sign.Verify(d.cfg.VerifyKey, self, self.Sig) || badRouteSig || badCapabilitySig {
			return fmt.Errorf("%w: bad authority or route signature", ErrNetmapIdentity)
		}
	}
	if d.cfg.VerifyPQKey != nil {
		badCapabilitySig := (self.Capabilities.Exit || self.Capabilities.Relay) &&
			!sign.VerifyCapabilitiesPQ(d.cfg.VerifyPQKey, self, self.PQCapabilitySig)
		if !sign.VerifyPQ(d.cfg.VerifyPQKey, self, self.PQSig) ||
			!sign.VerifyRoutesPQ(d.cfg.VerifyPQKey, self, self.PQRouteSig) || badCapabilitySig {
			return fmt.Errorf("%w: bad ML-DSA authority or route signature", ErrNetmapIdentity)
		}
	}
	return nil
}

func (d *Daemon) enableExitNAT() {
	d.natMu.Lock()
	defer d.natMu.Unlock()
	if d.exitNAT == nil {
		return
	}
	// On Windows a reconfigure can reinstall the tunnel service, recreating the
	// adapter with per-interface forwarding reset to Disabled — so the NAT must
	// be re-armed after every reconfigure there (Enable is idempotent: it
	// replaces the NetNat and re-enables forwarding). On Unix the adapter
	// persists, so re-arming would only churn nftables/pf for nothing.
	if d.natEnabled && runtime.GOOS != "windows" {
		return
	}
	iface := "ratelmesh0"
	if named, ok := d.engine.(wgengine.InterfaceNamer); ok && named.InterfaceName() != "" {
		iface = named.InterfaceName()
	}
	if err := d.exitNAT.Enable(meshCIDR, iface); err != nil {
		d.log.Error("exit NAT setup failed", "err", err)
		return
	}
	d.natEnabled = true
}

func (d *Daemon) disableExitNAT() {
	d.natMu.Lock()
	defer d.natMu.Unlock()
	if d.exitNAT == nil || !d.natEnabled {
		return
	}
	if err := d.exitNAT.Disable(); err != nil {
		d.log.Warn("exit NAT teardown failed", "err", err)
	}
	d.natEnabled = false
}

// Resolve looks up a MagicDNS name (e.g. "laptop.alice.ratelmesh.net"), returning the
// peer's mesh IP.
func (d *Daemon) Resolve(name string) (string, bool) {
	if ip, ok := d.zone.LookupA(name); ok {
		return ip.String(), true
	}
	if ip, ok := d.zone.LookupAAAA(name); ok {
		return ip.String(), true
	}
	return "", false
}

// DNSSuffix returns the MagicDNS domain suffix.
func (d *Daemon) DNSSuffix() string { return d.zone.Suffix() }

// refreshPaths updates each peer's candidate set and starts a bounded race over
// every usable address. Production engines probe from WireGuard's persistent
// socket, so success both proves reachability and opens the NAT mapping used by
// encrypted packets. The legacy disco socket remains a fallback for stub/older
// engines, but never decides a production WireGuard endpoint by itself.
func (d *Daemon) refreshPaths(peers []types.Node) {
	for _, p := range peers {
		eps := probeCandidateEndpoints(p.Endpoints)
		if len(eps) == 0 {
			continue
		}
		d.mu.Lock()
		pp := d.paths[p.Key]
		if pp == nil {
			pp = magicsock.NewPeerPath(p.Key)
			d.paths[p.Key] = pp
		}
		d.mu.Unlock()
		pp.SetCandidates(eps)
		if prober, ok := d.engine.(wgengine.EndpointProber); ok {
			d.startExactSocketProbe(p.Key, pp, eps, prober)
			continue
		}
		d.startLegacyDiscoProbe(p.Key, pp)
	}
}

// directProbeLoop repeats unresolved path races. NAT mappings and networks can
// change without a netmap version change, so probing only during registration
// leaves roaming peers permanently stuck on the first stale candidate.
func (d *Daemon) directProbeLoop(ctx context.Context) {
	const interval = 10 * time.Second
	// Align retries to wall-clock slots. Two peers may have started minutes
	// apart; process-relative tickers can then miss each other's short punching
	// windows forever. Normal clock synchronization puts both races in the same
	// three-second window without coordinator-side scheduling state.
	first := time.NewTimer(time.Until(time.Now().Truncate(interval).Add(interval)))
	defer first.Stop()
	select {
	case <-ctx.Done():
		return
	case <-first.C:
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		d.mu.Lock()
		peers := append([]types.Node(nil), d.lastNetmap.Peers...)
		d.mu.Unlock()
		d.refreshPaths(peers)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *Daemon) startExactSocketProbe(key types.Key, pp *magicsock.PeerPath, candidates []netip.AddrPort, prober wgengine.EndpointProber) {
	d.mu.Lock()
	if d.probing[key] {
		d.mu.Unlock()
		return
	}
	d.probing[key] = true
	runCtx := d.runCtx
	d.mu.Unlock()
	if runCtx == nil {
		runCtx = context.Background()
	}

	go func() {
		defer func() {
			d.mu.Lock()
			delete(d.probing, key)
			d.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(runCtx, 3*time.Second)
		defer cancel()
		type result struct {
			ep  netip.AddrPort
			err error
		}
		results := make(chan result, len(candidates))
		var networkErr error
		for _, candidate := range candidates {
			candidate := candidate
			go func() {
				err := prober.ProbeEndpoint(ctx, candidate)
				select {
				case results <- result{ep: candidate, err: err}:
				case <-ctx.Done():
				}
			}()
		}
		for range candidates {
			select {
			case got := <-results:
				if got.err != nil {
					if isLocalSocketBindingError(got.err) {
						networkErr = got.err
					}
					continue
				}
				beforeType, before := pp.Current()
				if !pp.ConfirmDirect(got.ep) {
					return
				}
				cancel()
				d.setPeerPathStatus(key, string(magicsock.PathDirect))
				if beforeType != magicsock.PathDirect || before != got.ep {
					d.log.Info("direct candidate confirmed", "peer", key.ShortString(), "endpoint", got.ep)
					d.reapplyNetmap()
				}
				return
			case <-ctx.Done():
				d.setUnconfirmedPathStatus(key)
				if networkErr != nil {
					d.recoverNetworkPath(networkErr)
				}
				return
			}
		}
		d.setUnconfirmedPathStatus(key)
		if networkErr != nil {
			d.recoverNetworkPath(networkErr)
		}
	}()
}

// isLocalSocketBindingError distinguishes a dead local UDP binding from an
// ordinary unreachable peer candidate. EADDRNOTAVAIL is what macOS returns when
// a persistent wireguard-go socket survives a Wi-Fi/hotspot interface change
// but its former source path no longer exists.
func isLocalSocketBindingError(err error) bool {
	return errors.Is(err, syscall.EADDRNOTAVAIL)
}

func (d *Daemon) startLegacyDiscoProbe(key types.Key, pp *magicsock.PeerPath) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := magicsock.ProbeAll(ctx, pp, 500*time.Millisecond); err == nil {
			d.setPeerPathStatus(key, string(magicsock.PathDirect))
			return
		}
		d.setUnconfirmedPathStatus(key)
	}()
}

func (d *Daemon) setUnconfirmedPathStatus(key types.Key) {
	d.mu.Lock()
	usingRelay := d.relayed[key] && d.bridge != nil
	d.mu.Unlock()
	if usingRelay {
		d.setPeerPathStatus(key, string(magicsock.PathRelay))
	} else {
		d.setPeerPathStatus(key, "-")
	}
}

func (d *Daemon) setPeerPathStatus(key types.Key, path string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pathType[key] = path
	for i := range d.status.Peers {
		if d.status.Peers[i].KeyShort == key.ShortString() && d.status.Peers[i].PathType != "exit" {
			d.status.Peers[i].PathType = path
		}
	}
}

func (d *Daemon) preferConfirmedEndpoint(key types.Key, endpoints []string) []string {
	result := append([]string(nil), endpoints...)
	d.mu.Lock()
	pp := d.paths[key]
	d.mu.Unlock()
	if pp == nil {
		return result
	}
	path, direct := pp.Current()
	if path != magicsock.PathDirect || !direct.IsValid() {
		return result
	}
	want := direct.String()
	for i, endpoint := range result {
		if endpoint == want {
			copy(result[1:i+1], result[0:i])
			result[0] = want
			break
		}
	}
	return result
}

// preferCandidateEndpoint moves the current liveness-selected candidate to the
// front because WireGuard accepts one endpoint per peer. The index is scoped to
// parsed physical candidates and is therefore independent of names, tenants,
// private subnet conventions and candidate ordering supplied by a deployment.
func (d *Daemon) preferCandidateEndpoint(key types.Key, endpoints []string) []string {
	result := append([]string(nil), endpoints...)
	candidates := probeCandidateEndpoints(endpoints)
	if len(candidates) < 2 {
		return result
	}
	d.mu.Lock()
	index := d.candidateIndex[key] % len(candidates)
	d.mu.Unlock()
	want := candidates[index].String()
	for i, endpoint := range result {
		parsed, err := netip.ParseAddrPort(endpoint)
		if err == nil && netip.AddrPortFrom(parsed.Addr().Unmap(), parsed.Port()).String() == want {
			copy(result[1:i+1], result[0:i])
			result[0] = endpoint
			break
		}
	}
	return result
}

func probeCandidateEndpoints(raw []string) []netip.AddrPort {
	seen := make(map[netip.AddrPort]bool)
	out := make([]netip.AddrPort, 0, len(raw))
	for _, candidate := range raw {
		ep, err := netip.ParseAddrPort(candidate)
		if err != nil || !ep.IsValid() || ep.Port() == 0 {
			continue
		}
		addr := ep.Addr().Unmap()
		if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || meshIPv4Prefix.Contains(addr) {
			continue
		}
		ep = netip.AddrPortFrom(addr, ep.Port())
		if !seen[ep] {
			seen[ep] = true
			out = append(out, ep)
		}
	}
	return out
}

func safePeerEndpoints(raw []string) []string {
	candidates := probeCandidateEndpoints(raw)
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate.String())
	}
	return out
}

var meshIPv4Prefix = netip.MustParsePrefix("100.64.0.0/10")

// preferSameNATPrivateEndpoints returns a stable copy of peerEndpoints. When
// self and peer advertise the same public IP and also have private candidates
// on the same local subnet, those private candidates are moved ahead of public
// and mesh candidates to avoid a dependency on NAT hairpinning. A shared public
// IP alone is not sufficient: guest/client-isolated LANs commonly use different
// RFC1918 subnets behind one edge NAT and cannot route between them.
func preferSameNATPrivateEndpoints(selfEndpoints, peerEndpoints []string) []string {
	result := append([]string(nil), peerEndpoints...)
	selfPublic := make(map[netip.Addr]struct{})
	var selfPrivate []netip.Addr
	for _, raw := range selfEndpoints {
		if ep, err := netip.ParseAddrPort(raw); err == nil {
			addr := ep.Addr().Unmap()
			if isPublicEndpointAddr(addr) {
				selfPublic[addr] = struct{}{}
			} else if addr.IsPrivate() {
				selfPrivate = append(selfPrivate, addr)
			}
		}
	}
	sharedPublic := false
	for _, raw := range peerEndpoints {
		ep, err := netip.ParseAddrPort(raw)
		if err != nil || !isPublicEndpointAddr(ep.Addr()) {
			continue
		}
		if _, ok := selfPublic[ep.Addr().Unmap()]; ok {
			sharedPublic = true
			break
		}
	}
	if !sharedPublic {
		return result
	}
	private := make([]string, 0, len(result))
	other := make([]string, 0, len(result))
	for _, raw := range result {
		ep, err := netip.ParseAddrPort(raw)
		if err == nil && privateEndpointLikelyReachable(selfPrivate, ep.Addr().Unmap()) {
			private = append(private, raw)
		} else {
			other = append(other, raw)
		}
	}
	return append(private, other...)
}

func privateEndpointLikelyReachable(self []netip.Addr, peer netip.Addr) bool {
	if !peer.IsPrivate() {
		return false
	}
	bits := 64
	if peer.Is4() {
		bits = 24
	}
	peerPrefix := netip.PrefixFrom(peer, bits).Masked()
	for _, addr := range self {
		if addr.BitLen() == peer.BitLen() && peerPrefix.Contains(addr) {
			return true
		}
	}
	return false
}

func isPublicEndpointAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsValid() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !meshIPv4Prefix.Contains(addr)
}

func (d *Daemon) currentPathType(k types.Key) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pathType[k]
}

// peerEndpoints returns the WireGuard endpoints to use for a peer and whether the
// relay bridge is in play. It routes through the relay when ForceRelay is set,
// the switch loop has marked this peer for relay fallback, or the peer advertises
// no direct endpoint; otherwise it uses the direct endpoints.
func (d *Daemon) peerEndpoints(p types.Node) ([]string, bool) {
	d.mu.Lock()
	bridge := d.bridge
	relayed := d.relayed[p.Key]
	d.mu.Unlock()
	return d.peerEndpointsWith(p, bridge, relayed)
}

func (d *Daemon) peerEndpointsWith(p types.Node, bridge *magicsock.RelayBridge, relayed bool) ([]string, bool) {
	force := d.cfg.ForceRelay
	if bridge != nil {
		bridge.Allow(p.Key) // a netmap member: allow lazy reverse-bridging (roaming)
		if force || relayed || len(p.Endpoints) == 0 {
			if ep, err := bridge.Endpoint(p.Key); err == nil {
				return []string{ep.String()}, true
			}
		}
	}
	if force {
		// Fail closed: -force-relay must never fall back to a direct endpoint (its
		// whole point is that traffic only ever goes via the relay). If the relay
		// is unavailable, advertise no endpoint so the peer is blackholed rather
		// than leaking over a direct path (security review).
		return nil, false
	}
	return p.Endpoints, false
}

// ensureRelay connects to the first reachable relay in addrs and starts the
// bridge + fallback loop, unless already connected. Trying the list in order
// gives redundancy/geo failover for the coord-advertised DERPMap. Idempotent;
// safe to call from Run (flag) or applyNetmap (DERPMap).
func (d *Daemon) ensureRelay(ctx context.Context, addrs []string) (connected bool) {
	// Serialize connect attempts. Without this, the reconnect loop and applyNetmap
	// could both dial and bind the same key; the relay supersedes the first
	// connection, whose close fires onRelayDisconnect and tears down the live
	// bridge — a reconnect storm (security review §2 follow-up).
	d.mu.Lock()
	if d.bridge != nil || d.relayDialing || len(addrs) == 0 {
		d.mu.Unlock()
		return false
	}
	d.relayDialing = true
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.relayDialing = false
		d.mu.Unlock()
	}()

	var rc *relay.Client
	var connectedAddr, connectedSpec string
	for _, spec := range addrs {
		if spec == "" {
			continue
		}
		// A relay spec may carry a camouflage transport (obfs/tls-camo/ws-camo) so
		// a fallback client can reach a disguised relay, not only a plain one (§5).
		addr, tr, clientSecret := parseRelaySpec(spec)
		// The daemon context lives for the whole process. Give each candidate its
		// own deadline so one black-holed IP cannot prevent failover to every relay
		// that follows it in the DERPMap.
		attemptCtx, cancel := context.WithTimeout(ctx, relayConnectTimeout)
		c, err := relay.DialWithAdmission(attemptCtx, addr, d.priv, tr, clientSecret)
		cancel()
		if err != nil {
			d.log.Debug("relay connect failed, trying next", "addr", addr, "err", err)
			continue
		}
		rc, connectedAddr, connectedSpec = c, addr, spec
		break
	}
	if rc == nil {
		d.log.Error("no advertised relay reachable; continuing without relay fallback", "tried", relaySpecAddresses(addrs))
		return false
	}

	wgAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), d.cfg.ListenPort)
	d.mu.Lock()
	if d.bridge != nil { // lost a race; another caller connected first
		d.mu.Unlock()
		_ = rc.Close()
		return false
	}
	d.relayClient = rc
	d.bridge = magicsock.NewRelayBridge(ctx, rc, wgAddr, d.log, d.onRelayDisconnect)
	d.relaySpec = connectedSpec
	// Use the resolved socket address (post-DNS) so the kill-switch TCP allow
	// works for hostname relays too, not just literal IPs (security review §3).
	var resolvedRelay netip.AddrPort
	if ra := rc.RemoteAddr(); ra != nil {
		resolvedRelay, _ = netip.ParseAddrPort(ra.String())
		d.relayAddr = resolvedRelay
	}
	d.mu.Unlock()

	// Seed the DNS cache with this known-good IP for a HOSTNAME relay, so the
	// kill-switch allow-list still has a reachable relay address even if later DNS
	// lookups fail while the tunnel is down (security review follow-up).
	if resolvedRelay.IsValid() {
		if specAddr, _, _ := parseRelaySpec(connectedSpec); specAddr != "" {
			if _, err := netip.ParseAddrPort(specAddr); err != nil { // hostname, not IP literal
				d.relayDNSPut(specAddr, []netip.AddrPort{resolvedRelay}, relayDNSTTL)
			}
		}
	}
	d.log.Info("relay fallback connected", "addr", connectedAddr, "forceRelay", d.cfg.ForceRelay)
	return true
}

const relayConnectTimeout = 10 * time.Second

// clearBridgeLocked tears down the current bridge bookkeeping and returns the old
// bridge AND relay client for the caller to close (outside the lock). Caller
// holds d.mu. It does NOT touch d.relayed: a peer's known-dead-direct decision is
// preserved across a relay drop, so on reconnect it goes straight back to the
// relay instead of re-trialing direct for the fallback window (security review
// §3). The client is returned separately because the bridge does not own it
// (§rotation leak): on rotation the old relay is still connected and must be
// closed, else its TCP conn + receive goroutine leak.
func (d *Daemon) clearBridgeLocked() (*magicsock.RelayBridge, *relay.Client) {
	b, c := d.bridge, d.relayClient
	d.bridge = nil
	d.relayClient = nil
	d.relayAddr = netip.AddrPort{}
	d.relaySpec = ""
	return b, c
}

// closeRelayResources closes a bridge and its relay client (nil-safe).
func closeRelayResources(b *magicsock.RelayBridge, c *relay.Client) {
	if b != nil {
		b.Close()
	}
	if c != nil {
		_ = c.Close()
	}
}

// onRelayDisconnect is invoked by the bridge when the relay link drops. It tears
// down the dead bridge, reverts peers to their direct endpoints, and re-programs
// the data plane — which reconnects the relay via applyNetmap (security review).
func (d *Daemon) onRelayDisconnect(from *magicsock.RelayBridge) {
	d.mu.Lock()
	if d.bridge != from {
		// Stale callback from a bridge we already rotated/replaced. Ignoring it is
		// essential: otherwise a rotated-out bridge's late disconnect would tear
		// down its live replacement, re-creating the reconnect storm (security
		// review). The replacement's own lifecycle handles its disconnects.
		d.mu.Unlock()
		return
	}
	old, oldClient := d.clearBridgeLocked()
	if d.relayed[d.exitPeerKey] {
		// The selected exit was using this relay. Its previous handshake proves
		// nothing about the replacement path, so remove defaults immediately and
		// require a new handshake before promoting it again.
		d.exitHandshakeAfter = time.Now()
		d.exitRouted = false
	}
	d.mu.Unlock()
	closeRelayResources(old, oldClient)
	// Re-program the data plane for the bridge-down state: relayed peers with no
	// bridge fall to direct (best effort) or, under force-relay, to no endpoint.
	// Their relayed flag is kept so reconnect restores the relay path immediately.
	d.log.Warn("relay disconnected; reconnecting")
	d.reapplyNetmap()
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	return uint16(n), err
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// parseRelaySpec parses a DERPMap relay entry. Plain form is "host:port"; a
// camouflage transport is appended pipe-delimited (§5, §8):
//
//	host:port|obfs|<pre-shared-secret>
//	host:port|tlscamo|<server-name>  (legacy; fails closed without a cert pin)
//	host:port|wscamo|<server-name>
//	host:port|wss|<server-name>      (ws-camo inside TLS; hides Host, blends with HTTPS)
func parseRelaySpec(spec string) (addr string, tr transport.Transport, clientSecret []byte) {
	parts := strings.Split(spec, "|")
	addr = parts[0]
	if len(parts) >= 4 {
		clientSecret = []byte(parts[3])
	}
	if len(parts) < 2 {
		return addr, transport.Plain{}, clientSecret
	}
	param := ""
	if len(parts) >= 3 {
		param = parts[2]
	}
	switch parts[1] {
	case "obfs":
		return addr, transport.NewObfs([]byte(param)), clientSecret
	case "tlscamo":
		return addr, transport.NewTLSCamoClient(param, nil), clientSecret
	case "wscamo":
		return addr, transport.NewWSCamoClient(param), clientSecret
	case "wss":
		return addr, transport.NewWSSCamoClient(param), clientSecret
	default:
		return addr, transport.New(parts[1], []byte(param)), clientSecret
	}
}

func relaySpecAddresses(specs []string) []string {
	addrs := make([]string, 0, len(specs))
	for _, spec := range specs {
		addr, _, _ := strings.Cut(spec, "|")
		if addr != "" {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

// relayReconnectLoop keeps the fallback relay connected: whenever the bridge is
// down and a relay is configured (flag or DERPMap), it retries with capped
// exponential backoff. Without this, a relay that is briefly unavailable would
// never be reconnected until an unrelated netmap change — black-holing traffic
// under -force-relay (security review §2).
func (d *Daemon) relayReconnectLoop(ctx context.Context) {
	const minBackoff, maxBackoff = 2 * time.Second, 30 * time.Second
	backoff := minBackoff
	t := time.NewTimer(backoff)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d.mu.Lock()
		down := d.bridge == nil
		specs := append([]string(nil), d.relaySpecs...)
		d.mu.Unlock()

		if down && len(specs) > 0 {
			if d.ensureRelay(ctx, specs) {
				backoff = minBackoff
				// Program peers onto the recovered relay now, rather than waiting for
				// the next netmap change (security review §1). Relayed / force-relay /
				// endpoint-less peers get their bridge endpoints back immediately.
				d.reapplyNetmap()
			} else if backoff < maxBackoff {
				backoff *= 2
			}
		} else {
			backoff = minBackoff
		}
		t.Reset(backoff)
	}
}

func (d *Daemon) closeRelay() {
	d.mu.Lock()
	rc, br := d.relayClient, d.bridge
	d.mu.Unlock()
	if br != nil {
		br.Close()
	}
	if rc != nil {
		_ = rc.Close()
	}
}

const (
	// candidateTrialAfter bounds how long a kernel WireGuard engine tries one
	// advertised physical endpoint before advancing to the next. macOS normally
	// confirms candidates faster through its exact-socket probe; this remains a
	// liveness-backed recovery path if that confirmation later goes stale.
	candidateTrialAfter = 6 * time.Second
	// relayFallbackAfter is how long a peer may sit on its direct endpoint with no
	// received-byte progress before the daemon reroutes it over the relay.
	relayFallbackAfter = 15 * time.Second
	// livenessWindow is how recently a peer must have received bytes to count as
	// having a working path. Keepalive (5s) keeps a live path well inside it.
	livenessWindow = 20 * time.Second
	// upgradeRetry is how long a relayed peer waits before re-trying its direct
	// path (a brief trial; if direct still fails it falls back again).
	upgradeRetry = 5 * time.Minute
	// exitHandshakeFresh is deliberately longer than WireGuard's normal rekey
	// interval. A selected exit loses its default routes if its handshake ages
	// beyond this window, restoring direct connectivity instead of leaving the
	// whole machine in a route blackhole.
	exitHandshakeFresh = 3 * time.Minute
	// A macOS userspace WireGuard socket can remain queryable after its UDP NAT
	// binding silently dies. Only count a meaningful burst of non-keepalive
	// traffic, and require it to remain unanswered across multiple health ticks,
	// before rebuilding the socket. The bounded window prevents tiny persistent
	// keepalives from accumulating into a false positive while the EXIT is idle.
	exitSilentPathWindow   = 15 * time.Second
	exitSilentPathMinAge   = 9 * time.Second
	exitSilentPathMinBytes = 4 << 10
	exitSilentPathCooldown = 45 * time.Second
)

var errExitSilentPath = errors.New("selected exit sent traffic without encrypted replies")

// relaySwitchLoop watches per-peer WireGuard received-byte liveness and moves a
// peer between its direct endpoint and the relay (DESIGN.md §3.2): it falls back
// to the relay when the direct path yields no traffic, and periodically re-tries
// direct so a recovered path is upgraded back off the relay. Persistent
// keepalives drive the traffic that makes liveness observable.
func (d *Daemon) relaySwitchLoop(ctx context.Context) {
	reporter, ok := d.engine.(wgengine.PeerStatsReporter)
	if !ok {
		d.log.Debug("relay fallback: engine has no stats reporter; auto-switch disabled")
		return
	}
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		stats, err := reporter.PeerStats()
		if err != nil {
			d.recordDataPlaneHealth(err)
			continue
		}
		d.recordDataPlaneHealth(nil)
		toRelay, toDirect := d.checkRelayTransitions(stats, time.Now())
		now := time.Now()
		silentExit, silentPath := d.checkSilentExitPathFailure(now)
		if silentPath {
			d.log.Warn("selected exit path stopped receiving; rebuilding WireGuard socket", "exit", silentExit)
			d.recoverSilentExitPath(now)
			continue
		}
		exitName, exitReady, exitChanged := d.checkExitRouteTransition(stats, now)
		trafficChanged := d.updateExitTrafficVerification(now)
		if len(toRelay) > 0 {
			d.log.Info("relay fallback: no traffic on direct path, routing peers over the relay", "peers", toRelay)
		}
		if len(toDirect) > 0 {
			d.log.Info("direct path retry: trying another candidate or upgrading from relay", "peers", toDirect)
		}
		if exitChanged {
			if exitReady {
				d.log.Info("exit handshake ready; enabling full-tunnel routes", "exit", exitName)
			} else {
				d.log.Warn("exit handshake stale; restoring direct egress", "exit", exitName)
			}
		}
		if trafficChanged {
			d.log.Info("exit traffic verified from encrypted receive progress", "exit", exitName)
		}
		if len(toRelay)+len(toDirect) > 0 || exitChanged {
			d.reapplyNetmap()
		}
	}
}

// checkSilentExitPathFailure recognizes a macOS-specific failure that handshake
// freshness cannot: applications keep entering WireGuard (TX advances) while
// the stale UDP/NAT path returns no encrypted packets at all. It is deliberately
// demand-driven, so an idle tunnel and its tiny persistent keepalives never flap.
func (d *Daemon) checkSilentExitPathFailure(now time.Time) (string, bool) {
	dataRecoverer, dataOK := d.engine.(wgengine.DataPlaneRecoverer)
	_, pathOK := d.engine.(wgengine.NetworkPathRecoverer)
	if !dataOK || !pathOK || !dataRecoverer.DataPlaneRecoveryEnabled() {
		return "", false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.exitRouted || d.exitPeerKey.IsZero() ||
		(!d.lastSilentPathRecovery.IsZero() && now.Sub(d.lastSilentPathRecovery) < exitSilentPathCooldown) {
		return "", false
	}
	since := d.txDemandSince[d.exitPeerKey]
	if since.IsZero() || now.Sub(since) < exitSilentPathMinAge ||
		now.Sub(since) > exitSilentPathWindow ||
		d.unansweredTx[d.exitPeerKey] < exitSilentPathMinBytes {
		return "", false
	}
	name := d.preferredExit
	for _, p := range d.lastNetmap.Peers {
		if p.Key == d.exitPeerKey {
			name = p.Name
			break
		}
	}
	d.lastSilentPathRecovery = now
	delete(d.unansweredTx, d.exitPeerKey)
	delete(d.txDemandSince, d.exitPeerKey)
	return name, true
}

// recoverSilentExitPath removes the default routes while the old interface is
// still present, then rebuilds the userspace utun/socket. The kill switch stays
// armed throughout, and a new handshake is required before /0 routes return.
func (d *Daemon) recoverSilentExitPath(now time.Time) {
	d.mu.Lock()
	if !d.exitRouted || d.lastNetmap.Version == 0 {
		d.mu.Unlock()
		return
	}
	previousHandshakeAfter := d.exitHandshakeAfter
	previousTrafficVerified := d.status.ExitTrafficVerified
	previousRXProgress, hadRXProgress := d.rxProgress[d.exitPeerKey]
	d.exitRouted = false
	d.exitHandshakeAfter = now.Add(time.Second)
	d.status.ExitTrafficVerified = false
	delete(d.rxProgress, d.exitPeerKey)
	nm := d.lastNetmap
	d.mu.Unlock()

	if err := d.applyNetmap(nm); err != nil {
		// applyNetmap is transactional: if staging failed, the live engine still
		// carries the old defaults. Restore matching bookkeeping so the next
		// health round does not mistake that configuration for a staged peer.
		d.mu.Lock()
		d.exitRouted = true
		d.exitHandshakeAfter = previousHandshakeAfter
		d.status.ExitTrafficVerified = previousTrafficVerified
		if hadRXProgress {
			d.rxProgress[d.exitPeerKey] = previousRXProgress
		}
		d.mu.Unlock()
		d.log.Error("silent exit recovery: failed to stage routes before socket rebuild", "err", err)
		return
	}
	d.recoverNetworkPath(errExitSilentPath)
}

// updateExitTrafficVerification upgrades the local status only after receive
// traffic advances after full-tunnel route installation. checkRelayTransitions
// updates rxProgress from the same authenticated WireGuard peer statistics just
// before this function runs.
func (d *Daemon) updateExitTrafficVerification(now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Keep a successful proof for the lifetime of this routed EXIT. Ordinary
	// idle time is not a failure; applyNetmap clears the proof whenever the route
	// is demoted, the selected peer changes, or a new path lifecycle begins.
	if d.exitRouted && d.status.ExitTrafficVerified {
		return false
	}
	verified := false
	if d.exitRouted && !d.exitPeerKey.IsZero() {
		progress := d.rxProgress[d.exitPeerKey]
		verified = !progress.IsZero() && progress.After(d.exitTrafficAfter) && now.Sub(progress) < livenessWindow
	}
	changed := d.status.ExitTrafficVerified != verified
	d.status.ExitTrafficVerified = verified
	return changed && verified
}

const dataPlaneRecoveryThreshold = 3

// recordDataPlaneHealth turns repeated engine-stat failures into a bounded
// self-heal. A single failed `wg show` is harmless; three consecutive failures
// after a netmap was applied indicate that the userspace tunnel disappeared or
// wedged. The recoverer owns process/interface replacement and config replay.
func (d *Daemon) recordDataPlaneHealth(healthErr error) {
	d.mu.Lock()
	if healthErr == nil {
		d.dataPlaneFailures = 0
		d.mu.Unlock()
		return
	}
	d.dataPlaneFailures++
	failures := d.dataPlaneFailures
	hasNetmap := d.lastNetmap.Version != 0
	if failures >= dataPlaneRecoveryThreshold {
		d.dataPlaneFailures = 0
	}
	d.mu.Unlock()
	if failures < dataPlaneRecoveryThreshold || !hasNetmap {
		return
	}
	d.demoteExitForInternetFallback(healthErr)
	recoverer, ok := d.engine.(wgengine.DataPlaneRecoverer)
	if !ok || !recoverer.DataPlaneRecoveryEnabled() {
		return
	}
	d.log.Warn("data plane health checks failed; attempting automatic recovery", "failures", failures, "err", healthErr)
	if err := recoverer.RecoverDataPlane(); err != nil {
		d.log.Error("automatic data plane recovery failed", "err", err)
		return
	}
	// A recovered macOS userspace tunnel receives a fresh utun name. Reapply the
	// guard policy immediately so its pass rule follows that interface instead
	// of remaining pinned to the dead predecessor.
	d.refreshKillSwitch()
	d.log.Info("automatic data plane recovery completed")
}

// recoverNetworkPath handles a macOS roaming failure that ordinary `wg show`
// health checks cannot see: the utun and IPC channel remain alive, while the
// persistent UDP socket returns EADDRNOTAVAIL for every peer. Only one probe
// round may rebuild the data plane at a time.
func (d *Daemon) recoverNetworkPath(pathErr error) {
	recoverer, ok := d.engine.(wgengine.NetworkPathRecoverer)
	if !ok {
		return
	}
	d.mu.Lock()
	if d.networkRecoveryInProgress || d.lastNetmap.Version == 0 {
		d.mu.Unlock()
		return
	}
	d.networkRecoveryInProgress = true
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.networkRecoveryInProgress = false
		d.mu.Unlock()
	}()

	d.demoteExitForInternetFallback(pathErr)
	d.log.Warn("physical network changed; rebuilding WireGuard socket", "err", pathErr)
	if err := recoverer.RecoverNetworkPath(); err != nil {
		d.log.Error("network-path data plane recovery failed", "err", err)
		return
	}
	d.refreshKillSwitch()
	d.log.Info("network-path data plane recovery completed")
}

func selectedExit(nm types.Netmap, preferred string) (bool, []string) {
	for _, p := range nm.Peers {
		if p.Role == types.RoleExit && peerMatches(p, preferred) {
			return true, append([]string(nil), p.Endpoints...)
		}
	}
	return false, nil
}

// demoteExitForInternetFallback removes full-tunnel routes before attempting a
// data-plane rebuild. It preserves the user's preferred exit so a later fresh
// handshake can promote it again without manual intervention.
func (d *Daemon) demoteExitForInternetFallback(reason error) {
	d.mu.Lock()
	if !d.internetFallback || !d.exitRouted {
		d.mu.Unlock()
		return
	}
	d.exitRouted = false
	d.exitHandshakeAfter = time.Now()
	delete(d.rxProgress, d.exitPeerKey)
	nm := d.lastNetmap
	d.mu.Unlock()
	d.log.Warn("internet fallback: restoring direct egress after data-plane failure", "err", reason)
	if err := d.applyNetmap(nm); err != nil {
		d.log.Error("internet fallback: direct-egress restore failed", "err", err)
	}
}

func requiresExitHandshake(engine wgengine.Engine) bool {
	gater, ok := engine.(wgengine.ExitHandshakeGater)
	return ok && gater.RequiresExitHandshake()
}

func handshakeIsFresh(st wgengine.PeerStat, now, after time.Time) bool {
	if st.LatestHandshake.IsZero() || now.Sub(st.LatestHandshake) > exitHandshakeFresh {
		return false
	}
	// `wg show` reports whole Unix seconds. The one-second tolerance avoids
	// rejecting a handshake completed in the same second as a path switch.
	return after.IsZero() || st.LatestHandshake.Add(time.Second).After(after)
}

// exitReadyForPeer decides whether applyNetmap may retain this peer's /0
// routes. A transient stats command failure preserves an already-active route;
// a new selection always starts staged and fail-open until a handshake proves
// it usable.
func (d *Daemon) exitReadyForPeer(key types.Key, now time.Time) bool {
	if !requiresExitHandshake(d.engine) {
		return true
	}
	reporter, ok := d.engine.(wgengine.PeerStatsReporter)
	if !ok {
		return false
	}
	stats, err := reporter.PeerStats()
	if err != nil {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.exitPeerKey == key && d.exitRouted
	}
	d.mu.Lock()
	after := time.Time{}
	if d.exitPeerKey == key {
		after = d.exitHandshakeAfter
	}
	d.mu.Unlock()
	st, ok := stats[key]
	return ok && handshakeIsFresh(st, now, after)
}

// checkExitRouteTransition tells the liveness loop when a staged exit can be
// promoted, or an active exit must be demoted because its handshake went stale.
func (d *Daemon) checkExitRouteTransition(stats map[types.Key]wgengine.PeerStat, now time.Time) (name string, ready, changed bool) {
	if !requiresExitHandshake(d.engine) {
		return "", false, false
	}
	d.mu.Lock()
	preferred := d.preferredExit
	nm := d.lastNetmap
	routedKey, routed, after := d.exitPeerKey, d.exitRouted, d.exitHandshakeAfter
	d.mu.Unlock()
	for _, p := range nm.Peers {
		if p.Role != types.RoleExit || !peerMatches(p, preferred) {
			continue
		}
		st, ok := stats[p.Key]
		if routedKey != p.Key {
			after = time.Time{}
		}
		ready = ok && handshakeIsFresh(st, now, after)
		return p.Name, ready, routedKey != p.Key || routed != ready
	}
	return "", false, false
}

// checkRelayTransitions updates per-peer liveness from the stats snapshot and
// decides fallbacks (direct->relay when a direct path is dead) and upgrade trials
// (relay->direct after upgradeRetry). It returns the names moved each way. Split
// out from the loop so the decision is unit-testable.
func (d *Daemon) checkRelayTransitions(stats map[types.Key]wgengine.PeerStat, now time.Time) (toRelay, toDirect []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.lastTx == nil {
		d.lastTx = make(map[types.Key]int64)
	}
	if d.unansweredTx == nil {
		d.unansweredTx = make(map[types.Key]int64)
	}
	if d.txDemandSince == nil {
		d.txDemandSince = make(map[types.Key]time.Time)
	}
	for _, p := range d.lastNetmap.Peers {
		key := p.Key
		// Update received-byte liveness and demand-driven silent-path accounting.
		// The first TX sample is only a baseline: cumulative bytes from before the
		// daemon started must not masquerade as a new unanswered request.
		stat := stats[key]
		rx := stat.RxBytes
		previousRx := d.lastRx[key]
		if rx > previousRx {
			d.rxProgress[key] = now
			delete(d.unansweredTx, key)
			delete(d.txDemandSince, key)
		} else if rx < previousRx {
			delete(d.unansweredTx, key)
			delete(d.txDemandSince, key)
		}
		d.lastRx[key] = rx
		tx := stat.TxBytes
		previousTx, txSeen := d.lastTx[key]
		if !txSeen || tx < previousTx {
			delete(d.unansweredTx, key)
			delete(d.txDemandSince, key)
		} else if tx > previousTx && rx == previousRx {
			since := d.txDemandSince[key]
			if since.IsZero() || now.Sub(since) > exitSilentPathWindow {
				d.txDemandSince[key] = now
				d.unansweredTx[key] = tx - previousTx
			} else {
				d.unansweredTx[key] += tx - previousTx
			}
		}
		d.lastTx[key] = tx
		prog := d.rxProgress[key]
		if !p.Online {
			// Coordinator presence is authoritative for path trials. Cycling the
			// stale private/IPv6 candidates of an offline phone or laptop cannot
			// recover it, but every candidate change reconfigures the shared
			// WireGuard interface and can briefly disturb a healthy EXIT peer.
			// Refresh the trial baseline so a peer that returns online receives a
			// complete candidate window instead of rotating immediately.
			d.directSince[key] = now
			continue
		}
		if d.cfg.ForceRelay || len(p.Endpoints) == 0 {
			continue // liveness is recorded, but there is no path switch to decide
		}
		servingExit := d.cfg.Role == types.RoleExit ||
			d.lastNetmap.Self.Capabilities.Exit ||
			d.lastNetmap.Self.Role == types.RoleExit
		usesThisExit := d.lastNetmap.Self.ID != "" &&
			p.SelectedExitID == d.lastNetmap.Self.ID
		if servingExit && !usesThisExit {
			// An exit server can see many coordinator-online peers that are not
			// using it. Proactively cycling their stale candidates rebuilds the
			// shared WireGuard interface every few seconds and can interrupt the
			// clients that are using the exit. WireGuard handshake and keepalive
			// bytes are indistinguishable from application demand in aggregate
			// peer counters, so they cannot safely enable retries here. Netmap
			// endpoint changes and peer-initiated handshakes still establish the
			// path; a peer selecting this exit keeps proactive recovery because
			// it needs a ready return path.
			d.directSince[key] = now
			continue
		}

		if !d.relayed[key] {
			// On the direct path: fall back if it produces no traffic in time.
			since, seen := d.directSince[key]
			if !seen {
				d.directSince[key] = now
				continue
			}
			healthy := handshakeIsFresh(stats[key], now, since) ||
				(!prog.IsZero() && prog.After(since) && now.Sub(prog) < livenessWindow)
			candidates := probeCandidateEndpoints(p.Endpoints)
			// Without a relay there is no terminal fallback: keep cycling the
			// complete dynamic candidate set so a restarted peer or changed NAT
			// binding can recover without restarting this daemon. When a relay is
			// available, try each direct candidate once before falling back to it.
			candidateAvailable := d.bridge == nil || d.candidateAttempts[key] < len(candidates)-1
			if !healthy && len(candidates) > 1 && now.Sub(since) > candidateTrialAfter && candidateAvailable {
				if d.candidateIndex == nil {
					d.candidateIndex = make(map[types.Key]int)
				}
				if d.candidateAttempts == nil {
					d.candidateAttempts = make(map[types.Key]int)
				}
				d.candidateIndex[key] = (d.candidateIndex[key] + 1) % len(candidates)
				d.candidateAttempts[key]++
				d.directSince[key] = now
				d.rxProgress[key] = time.Time{}
				if pp := d.paths[key]; pp != nil {
					pp.LoseDirect()
				}
				if peerMatches(p, d.preferredExit) {
					d.exitHandshakeAfter = now
				}
				toDirect = append(toDirect, p.Name)
				continue
			}
			// A fallback decision is meaningful only while a relay bridge exists.
			// Otherwise the peer stays on the same direct endpoint but EXIT starts
			// demanding a newer handshake forever.
			if d.bridge != nil && !healthy && now.Sub(since) > relayFallbackAfter {
				d.relayed[key] = true
				d.relaySince[key] = now
				d.rxProgress[key] = time.Time{} // give the relay path a fresh window
				if peerMatches(p, d.preferredExit) {
					d.exitHandshakeAfter = now
				}
				toRelay = append(toRelay, p.Name)
			}
			continue
		}
		// On the relay: once it is working, periodically trial the direct path.
		relaySince := d.relaySince[key]
		healthy := handshakeIsFresh(stats[key], now, relaySince) ||
			(!prog.IsZero() && (relaySince.IsZero() || prog.After(relaySince)) && now.Sub(prog) < livenessWindow)
		if healthy {
			// An exit node is the return path for every client currently using it.
			// Replacing a proven relay endpoint with a speculative direct endpoint
			// makes that path asymmetric: the client still sends exit traffic over
			// the relay while replies are sent to a filtered direct address. Keep
			// relayed clients pinned on exit nodes; a netmap endpoint change or a
			// daemon restart still performs fresh path discovery.
			if d.cfg.Role == types.RoleExit || d.lastNetmap.Self.Capabilities.Exit || d.lastNetmap.Self.Role == types.RoleExit {
				continue
			}
			// Never disrupt the exit currently carrying the host's default route.
			// A direct-path trial replaces the working relay endpoint immediately;
			// on relay-only networks that withdraws the exit for 15-30 seconds every
			// upgradeRetry interval. Active exits stay on their proven relay path;
			// clearing/reselecting the exit or an endpoint change still restarts path
			// discovery without periodically blackholing all application traffic.
			if peerMatches(p, d.preferredExit) {
				continue
			}
			if since, ok := d.relaySince[key]; ok && now.Sub(since) > upgradeRetry {
				d.relayed[key] = false
				d.directSince[key] = now
				d.rxProgress[key] = time.Time{} // direct must prove itself anew
				if peerMatches(p, d.preferredExit) {
					d.exitHandshakeAfter = now
				}
				toDirect = append(toDirect, p.Name)
			}
		}
	}
	return toRelay, toDirect
}

// reapplyNetmap re-programs the data plane from the last netmap (used after a
// relay-fallback decision changes a peer's endpoint).
func (d *Daemon) reapplyNetmap() {
	d.mu.Lock()
	nm := d.lastNetmap
	d.mu.Unlock()
	if nm.Version == 0 {
		return
	}
	if err := d.applyNetmap(nm); err != nil {
		d.log.Error("relay fallback reapply failed", "err", err)
	}
}

func parseAddrPorts(ss []string) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(ss))
	seen := make(map[netip.AddrPort]bool)
	for _, s := range ss {
		if ap, err := netip.ParseAddrPort(s); err == nil {
			ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
			if seen[ap] {
				continue
			}
			seen[ap] = true
			out = append(out, ap)
		}
	}
	return out
}

func physicalTransportAddrs(endpoints []string) []netip.Addr {
	var out []netip.Addr
	for _, endpoint := range parseAddrPorts(endpoints) {
		addr := endpoint.Addr().Unmap()
		// A peer may advertise its Mesh address as a low-priority candidate. It
		// is an inner-tunnel destination, never an outer physical transport.
		// Pinning it through the LAN gateway creates a competing /32 route that
		// steals Mesh TCP replies from the utun.
		if !meshIPv4Prefix.Contains(addr) {
			out = append(out, addr)
		}
	}
	return out
}

// livePeerEndpoints returns WireGuard's authenticated current peer endpoints.
// A peer behind symmetric NAT can arrive from a translated port that was never
// advertised through the coordinator. WireGuard securely roams to that source,
// so the live engine is the only authoritative place to learn the transport
// that PF must preserve before the EXIT kill switch is armed.
func (d *Daemon) livePeerEndpoints() []string {
	reporter, ok := d.engine.(wgengine.PeerStatsReporter)
	if !ok {
		return nil
	}
	stats, err := reporter.PeerStats()
	if err != nil {
		d.log.Warn("kill switch: read live peer endpoints failed", "err", err)
		return nil
	}
	endpoints := make([]string, 0, len(stats))
	for _, stat := range stats {
		if stat.Endpoint.IsValid() {
			endpoints = append(endpoints, stat.Endpoint.String())
		}
	}
	return endpoints
}

// refreshKillSwitch arms or disarms the fail-closed firewall from the latest
// authoritative daemon state. It stays armed whenever an exit is selected,
// including handshake recovery, so loss of either IPv4 or IPv6 tunnel routes
// cannot fall back to the physical network.
func (d *Daemon) refreshKillSwitch() bool {
	if d.guard == nil {
		return d.recordKillSwitchStatus(false)
	}
	for attempt := 0; attempt < 3; attempt++ {
		// Potentially blocking engine and DNS work stays outside applyMu. Snapshot
		// the inputs first, prepare the EXIT half, then accept it only if those
		// authoritative inputs are unchanged after entering the transaction.
		snapshot := d.killSwitchRefreshSnapshot()
		liveEndpoints := d.livePeerEndpoints()
		exitSelected, exitEndpoints := selectedExit(snapshot.netmap, snapshot.preferredExit)
		for _, peer := range snapshot.netmap.Peers {
			exitEndpoints = append(exitEndpoints, peer.Endpoints...)
		}
		exitEndpoints = append(exitEndpoints, liveEndpoints...)
		policy := d.killSwitchPolicyForRelay(
			exitSelected, exitEndpoints, snapshot.internetFallback,
			snapshot.relaySpecs, snapshot.relayAddr,
		)

		d.applyMu.Lock()
		if !d.killSwitchRefreshStillCurrent(snapshot) {
			d.applyMu.Unlock()
			continue
		}
		current := d.guard.Current()
		copyRemotePolicy(&policy, current)
		if namer, ok := d.engine.(wgengine.InterfaceNamer); ok && namer.InterfaceName() != "" && policy.Active() {
			policy.TunnelInterface = namer.InterfaceName()
		}
		if reflect.DeepEqual(current, policy) {
			enabled := d.recordKillSwitchStatus(policy.Enabled)
			d.applyMu.Unlock()
			return enabled
		}
		if err := d.applyKillSwitchPolicy(policy); err != nil {
			d.recordKillSwitchStatus(false)
			d.applyMu.Unlock()
			return false
		}
		enabled := d.recordKillSwitchStatus(policy.Enabled)
		d.applyMu.Unlock()
		return enabled
	}
	d.log.Warn("kill switch refresh skipped because network intent kept changing")
	d.applyMu.Lock()
	enabled := d.recordKillSwitchStatus(d.guard.Current().Enabled)
	d.applyMu.Unlock()
	return enabled
}

type killSwitchRefreshState struct {
	netmap           types.Netmap
	preferredExit    string
	internetFallback bool
	relaySpecs       []string
	relayAddr        netip.AddrPort
}

func (d *Daemon) killSwitchRefreshSnapshot() killSwitchRefreshState {
	d.mu.Lock()
	defer d.mu.Unlock()
	nm := d.lastNetmap
	nm.Peers = append([]types.Node(nil), nm.Peers...)
	for i := range nm.Peers {
		nm.Peers[i].Endpoints = append([]string(nil), nm.Peers[i].Endpoints...)
	}
	return killSwitchRefreshState{
		netmap: nm, preferredExit: d.preferredExit, internetFallback: d.internetFallback,
		relaySpecs: append([]string(nil), d.relaySpecs...), relayAddr: d.relayAddr,
	}
}

func (d *Daemon) killSwitchRefreshStillCurrent(snapshot killSwitchRefreshState) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastNetmap.Version == snapshot.netmap.Version &&
		d.preferredExit == snapshot.preferredExit &&
		d.internetFallback == snapshot.internetFallback &&
		d.relayAddr == snapshot.relayAddr &&
		slices.Equal(d.relaySpecs, snapshot.relaySpecs)
}

// recordKillSwitchStatus runs before refreshKillSwitch releases applyMu, so a
// newer netmap transaction cannot commit its firewall and status between those
// writes and then be overwritten by a stale recovery result.
func (d *Daemon) recordKillSwitchStatus(enabled bool) bool {
	d.mu.Lock()
	d.status.KillSwitch = enabled
	d.mu.Unlock()
	return enabled
}

func (d *Daemon) killSwitchPolicy(exitSelected bool, exitEndpoints []string, internetFallback bool, specs []string) netguard.Policy {
	d.mu.Lock()
	relayAddr := d.relayAddr
	d.mu.Unlock()
	return d.killSwitchPolicyForRelay(exitSelected, exitEndpoints, internetFallback, specs, relayAddr)
}

func (d *Daemon) killSwitchPolicyForRelay(exitSelected bool, exitEndpoints []string, internetFallback bool, specs []string, relayAddr netip.AddrPort) netguard.Policy {
	armed := d.cfg.KillSwitch && !internetFallback && exitSelected
	if !armed {
		return netguard.Policy{}
	}
	// Allow the relay's TCP port through the kill switch — the CONNECTED relay AND
	// every candidate in the DERPMap/flag. If the bridge is down, the connected
	// address is empty, so without the candidates the kill switch would block the
	// very relay reconnection needed to restore the tunnel (security review §1).
	relayEndpoints := d.relayAllowEndpoints(relayAddr, specs)
	policy := netguard.Policy{
		Enabled:          armed,
		AllowCIDRs:       netguard.DefaultAllowCIDRs(),
		TunnelEndpoints:  parseAddrPorts(exitEndpoints),
		RelayEndpoints:   relayEndpoints,
		ControlEndpoints: d.controlAllowEndpoints(),
	}
	// Allow traffic out the WireGuard interface, or full-tunnel app packets (which
	// hit OUTPUT with a public dest before encapsulation) are dropped by the kill
	// switch, breaking exit egress rather than just preventing leaks.
	if namer, ok := d.engine.(wgengine.InterfaceNamer); ok {
		policy.TunnelInterface = namer.InterfaceName()
	}
	return policy
}

func (d *Daemon) applyKillSwitchPolicy(policy netguard.Policy) error {
	if err := d.guard.Apply(policy); err != nil {
		// Do NOT report the kill switch as armed when the firewall failed to load:
		// status would show KillSwitch:true with no rules in place, a false sense of
		// leak protection on the exact tool meant to prevent leaks.
		d.log.Error("kill switch apply failed — reporting DISARMED", "err", err)
		return fmt.Errorf("apply kill switch policy: %w", err)
	}
	return nil
}

func (d *Daemon) controlAllowEndpoints() []netip.AddrPort {
	u, err := url.Parse(d.cfg.CoordURL)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	portNumber, err := parsePort(port)
	if err != nil {
		return nil
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.AddrPort{netip.AddrPortFrom(addr.Unmap(), portNumber)}
	}
	return d.resolveRelayHost(net.JoinHostPort(host, port), host, port)
}

// exitPhysicalEndpoints returns every live bootstrap IP that must bypass the
// exit tunnel: the coordinator (HTTPS polling/registration) and the connected
// plus advertised relay candidates. The engine pins these before installing
// split-default routes, breaking the relay-needs-the-tunnel circular dependency.
func (d *Daemon) exitPhysicalEndpoints(specs []string) []netip.Addr {
	seen := make(map[netip.Addr]bool)
	var out []netip.Addr
	add := func(addr netip.Addr) {
		addr = addr.Unmap()
		if !addr.IsValid() || !addr.IsGlobalUnicast() || seen[addr] {
			return
		}
		seen[addr] = true
		out = append(out, addr)
	}

	if u, err := url.Parse(d.cfg.CoordURL); err == nil {
		host := u.Hostname()
		if addr, err := netip.ParseAddr(host); err == nil {
			add(addr)
		} else if host != "" {
			port := u.Port()
			if port == "" {
				if u.Scheme == "http" {
					port = "80"
				} else {
					port = "443"
				}
			}
			cacheKey := net.JoinHostPort(host, port)
			for _, ap := range d.resolveRelayHost(cacheKey, host, port) {
				add(ap.Addr())
			}
		}
	}

	// When the control plane rides a camouflage transport, the socket dials the
	// front door, NOT the coordinator host — so it is the front door that must
	// bypass the exit, or a tunnel drop severs the very connection used to recover
	// (the coordinator pin above would then guard an address nothing connects to).
	if d.cfg.CoordTransport != "" {
		if frontDoor, _ := coordFrontDoor(d.cfg.CoordURL, d.cfg.CoordFrontDoor); frontDoor != "" {
			if host, port, err := net.SplitHostPort(frontDoor); err == nil && host != "" {
				if addr, err := netip.ParseAddr(host); err == nil {
					add(addr)
				} else {
					for _, ap := range d.resolveRelayHost(net.JoinHostPort(host, port), host, port) {
						add(ap.Addr())
					}
				}
			}
		}
	}

	// Public-endpoint discovery must bypass the exit too. Otherwise enabling /0
	// sends STUN through the tunnel, the client drops its local reflexive
	// candidate, and same-NAT peers oscillate back to an unusable hairpin path.
	if host, port, err := net.SplitHostPort(d.cfg.STUNAddr); err == nil {
		if addr, err := netip.ParseAddr(host); err == nil {
			add(addr)
		} else {
			for _, ap := range d.resolveRelayHost(net.JoinHostPort(host, port), host, port) {
				add(ap.Addr())
			}
		}
	}

	d.mu.Lock()
	relayAddr := d.relayAddr
	d.mu.Unlock()
	for _, ap := range d.relayAllowEndpoints(relayAddr, specs) {
		add(ap.Addr())
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return out
}

// relayAllowEndpoints resolves the relay addresses the kill switch must permit:
// the currently-connected one plus every configured candidate (so reconnection
// is never blocked). Hostname specs are resolved best-effort.
func (d *Daemon) relayAllowEndpoints(connected netip.AddrPort, specs []string) []netip.AddrPort {
	seen := map[netip.AddrPort]bool{}
	var out []netip.AddrPort
	add := func(ap netip.AddrPort) {
		if ap.IsValid() && !seen[ap] {
			seen[ap] = true
			out = append(out, ap)
		}
	}
	add(connected)
	for _, spec := range specs {
		addr, _, _ := parseRelaySpec(spec)
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		p, err := netip.ParseAddrPort(addr)
		if err == nil {
			add(p) // IP literal
			continue
		}
		// Hostname: serve from the TTL cache, else resolve (best-effort, short
		// timeout) and cache — avoids a DNS lookup on every armed apply.
		for _, ap := range d.resolveRelayHost(addr, host, port) {
			add(ap)
		}
	}
	return out
}

// resolveRelayHost returns the resolved endpoints for a relay hostname spec,
// using a short-TTL cache so repeated kill-switch applies don't re-resolve.
// Crucially, a failed refresh (empty lookup — DNS may be unavailable or routed
// through the now-broken tunnel while the kill switch is armed) must NOT blank a
// previously-good result: doing so would empty the kill-switch relay allow-list
// and block the very reconnect that restores the tunnel (security review). We
// keep serving the last-known-good IPs and only retry sooner.
func (d *Daemon) resolveRelayHost(addr, host, port string) []netip.AddrPort {
	now := time.Now()
	d.relayDNSMu.Lock()
	prev, hadPrev := d.relayDNSCache[addr]
	if hadPrev && now.Before(prev.expiry) {
		addrs := prev.addrs
		d.relayDNSMu.Unlock()
		return addrs // fresh cache hit
	}
	d.relayDNSMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	ips, _ := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	cancel()
	var resolved []netip.AddrPort
	if pnum, perr := parsePort(port); perr == nil {
		for _, ip := range ips {
			resolved = append(resolved, netip.AddrPortFrom(ip.Unmap(), pnum))
		}
	}

	if len(resolved) > 0 {
		d.relayDNSPut(addr, resolved, relayDNSTTL)
		return resolved
	}
	// Lookup failed/empty. Keep the last-known-good IPs (retry soon) rather than
	// blanking the allow-list; only cache an empty negative result when there was
	// no prior positive entry.
	if hadPrev && len(prev.addrs) > 0 {
		d.relayDNSPut(addr, prev.addrs, relayDNSRetryTTL)
		return prev.addrs
	}
	d.relayDNSPut(addr, nil, relayDNSRetryTTL)
	return nil
}

// relayDNSPut stores a relay hostname's resolved endpoints with the given TTL.
func (d *Daemon) relayDNSPut(addr string, addrs []netip.AddrPort, ttl time.Duration) {
	d.relayDNSMu.Lock()
	defer d.relayDNSMu.Unlock()
	if d.relayDNSCache == nil {
		d.relayDNSCache = make(map[string]relayDNSEntry)
	}
	d.relayDNSCache[addr] = relayDNSEntry{addrs: addrs, expiry: time.Now().Add(ttl)}
}

// effectiveDNS reports the resolver actually in force. Tunnel DNS is only truly
// enforced when a MagicDNS server is running to redirect queries; without one,
// -tunnel-dns cannot take effect, so status must not claim it does (security
// review §4).
func (d *Daemon) effectiveDNS(exitActive bool) string {
	d.mu.Lock()
	haveDNS := d.dnsServer != nil
	d.mu.Unlock()
	if exitActive && d.cfg.TunnelDNS != "" && haveDNS {
		return d.cfg.TunnelDNS
	}
	return "system"
}

// updateDNSUpstreams enforces DNS-leak protection: while an exit is active and a
// tunnel resolver is configured, the MagicDNS server forwards ONLY to that
// resolver (reached through the tunnel), never the local/ISP resolvers. When the
// exit clears, it reverts to the system upstreams (DESIGN.md §3.3).
func (d *Daemon) updateDNSUpstreams(exitActive bool) {
	d.mu.Lock()
	srv := d.dnsServer
	system := d.dnsSystemUpstrms
	resolver := d.systemResolver
	tunnelMode := exitActive && d.cfg.TunnelDNS != ""
	modeChanged := !d.dnsModeKnown || d.dnsTunnelMode != tunnelMode
	d.dnsModeKnown = true
	d.dnsTunnelMode = tunnelMode
	d.mu.Unlock()
	if srv == nil {
		return
	}
	if tunnelMode {
		srv.SetUpstreams([]string{normalizeResolver(d.cfg.TunnelDNS)})
	} else {
		srv.SetUpstreams(system)
	}
	if modeChanged && resolver != nil {
		if err := resolver.FlushCache(); err != nil {
			d.log.Warn("DNS cache flush after upstream switch failed", "err", err)
		}
	}
}

// normalizeResolver turns a bare host into host:53 (the tunnel resolver is a
// plain UDP DNS server reachable through the tunnel; DoH is a later addition).
func normalizeResolver(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, "53")
}

// SetExit selects an exit node by name or mesh IP and re-applies routing. It
// errors if no online exit peer matches, so the CLI can report a clear failure.
func (d *Daemon) SetExit(nameOrIP string) error {
	d.applyMu.Lock()
	d.mu.Lock()
	nm := d.lastNetmap
	d.mu.Unlock()

	var match *types.Node
	for i := range nm.Peers {
		p := nm.Peers[i]
		if p.Role == types.RoleExit && peerMatches(p, nameOrIP) {
			match = &nm.Peers[i]
			break
		}
	}
	if match == nil {
		d.applyMu.Unlock()
		return fmt.Errorf("no exit node matching %q (use `ratelmesh exit list`)", nameOrIP)
	}
	d.mu.Lock()
	previous := d.preferredExit
	d.preferredExit = nameOrIP
	d.mu.Unlock()
	reapply, err := d.applyNetmapLocked(nm)
	if err != nil {
		d.mu.Lock()
		d.preferredExit = previous
		d.mu.Unlock()
		d.applyMu.Unlock()
		return err
	}
	if err := savePreferredExit(d.cfg.StateDir, nameOrIP); err != nil {
		d.log.Warn("persist preferred exit failed", "err", err)
	}
	d.applyMu.Unlock()
	if reapply {
		d.reapplyNetmap()
	}
	return nil
}

// ClearExit stops routing through any exit node (direct egress resumes).
func (d *Daemon) ClearExit() error {
	// Persist the safer DIRECT intent before waiting for applyMu. If route
	// application is wedged and the daemon is restarted, startup must not read
	// the old EXIT preference and re-arm its fail-closed routes/firewall.
	if err := savePreferredExit(d.cfg.StateDir, ""); err != nil {
		return fmt.Errorf("persist direct egress preference: %w", err)
	}
	d.applyMu.Lock()
	d.mu.Lock()
	previous := d.preferredExit
	d.preferredExit = ""
	nm := d.lastNetmap
	d.mu.Unlock()
	reapply, err := d.applyNetmapLocked(nm)
	if err != nil {
		d.mu.Lock()
		d.preferredExit = previous
		d.mu.Unlock()
		if persistErr := savePreferredExit(d.cfg.StateDir, previous); persistErr != nil {
			d.log.Error("restore preferred exit after failed clear", "err", persistErr)
		}
		d.applyMu.Unlock()
		return err
	}
	d.applyMu.Unlock()
	if reapply {
		d.reapplyNetmap()
	}
	return nil
}

// SetInternetFallback selects availability over leak protection. When enabled,
// the kill switch is disarmed and stale/failed exit routes are allowed to fall
// back to the host's physical internet connection.
func (d *Daemon) SetInternetFallback(enabled bool) error {
	d.mu.Lock()
	previous := d.internetFallback
	d.internetFallback = enabled
	nm := d.lastNetmap
	d.mu.Unlock()
	if err := d.applyNetmap(nm); err != nil {
		d.mu.Lock()
		d.internetFallback = previous
		d.mu.Unlock()
		return err
	}
	if err := saveInternetFallback(d.cfg.StateDir, enabled); err != nil {
		d.log.Warn("persist internet fallback failed", "err", err)
	}
	return nil
}

// peerMatches reports whether a peer is identified by the given name or mesh IP.
func peerMatches(p types.Node, nameOrIP string) bool {
	if p.Name == nameOrIP {
		return true
	}
	for _, a := range p.MeshIPs {
		if a.String() == nameOrIP {
			return true
		}
	}
	return false
}

// stripDefaultRoutes removes 0.0.0.0/0 and ::/0 from a peer's allowed IPs.
func stripDefaultRoutes(in []netip.Prefix) []netip.Prefix {
	out := in[:0:0]
	for _, p := range in {
		if p.Bits() == 0 {
			continue // default route
		}
		out = append(out, p)
	}
	return out
}

func hasIPv4DefaultOnly(prefixes []netip.Prefix) bool {
	var v4, v6 bool
	for _, prefix := range prefixes {
		if prefix.Bits() != 0 {
			continue
		}
		if prefix.Addr().Is4() {
			v4 = true
		} else {
			v6 = true
		}
	}
	return v4 && !v6
}

func defaultIPv6BlockRoutes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("::/1"),
		netip.MustParsePrefix("8000::/1"),
	}
}

// keepMeshOnly retains only the prefixes that are one of the peer's own mesh
// addresses (a single-host prefix matching a mesh IP), dropping advertised
// subnet routes the user has not accepted.
func keepMeshOnly(in []netip.Prefix, meshIPs []netip.Addr) []netip.Prefix {
	isMesh := make(map[netip.Addr]bool, len(meshIPs))
	for _, a := range meshIPs {
		isMesh[a] = true
	}
	out := in[:0:0]
	for _, p := range in {
		if p.IsSingleIP() && isMesh[p.Addr()] {
			out = append(out, p)
		}
	}
	return out
}

func keepMeshAndDefaults(in []netip.Prefix, meshIPs []netip.Addr) []netip.Prefix {
	out := keepMeshOnly(in, meshIPs)
	for _, prefix := range in {
		if prefix.Bits() == 0 {
			out = append(out, prefix)
		}
	}
	return out
}

// Status returns the current snapshot for the local API.
func (d *Daemon) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.status
	s.State = d.state
	s.Peers = append([]PeerStatus(nil), d.status.Peers...)
	now := time.Now()
	for i, peer := range d.lastNetmap.Peers {
		if i >= len(s.Peers) {
			break
		}
		services := d.remoteAccess.servicesFor(peer, now)
		s.Peers[i].RemoteServices = services
		s.Peers[i].RemoteAccessAllowed = len(services) > 0
	}
	s.ExitClients = append([]ExitClientStatus(nil), d.status.ExitClients...)
	return s
}

func (d *Daemon) setState(s BackendState) {
	d.mu.Lock()
	d.state = s
	d.status.State = s
	d.mu.Unlock()
}

// markControlRetrying preserves a working data plane while the long-poll
// control connection reconnects. Before the first netmap the daemon is truly
// Starting; afterwards the last authenticated netmap, routes and relay bridge
// remain usable and the UI must not claim the tunnel is still starting.
func (d *Daemon) markControlRetrying() {
	d.mu.Lock()
	if d.lastNetmap.Version == 0 {
		d.state = StateStarting
	} else {
		d.state = StateRunning
	}
	d.status.State = d.state
	d.mu.Unlock()
}

// localEndpoints returns this host's local-interface candidates at the actual
// WireGuard listen port. Do not append DiscoverReflexive here: that helper uses
// a short-lived, separately-bound UDP socket, so its NAT port is neither owned
// by WireGuard nor stable across polls. Advertising it made every poll mutate
// the netmap and could drive the coordinator into a hot loop. STUN discovery
// for a persistent socket belongs to the separate disco responder.
func (d *Daemon) localEndpoints() []string {
	// Under -force-relay, never advertise a direct endpoint: if peers learned it
	// they could send us direct packets and WireGuard would roam our session onto
	// the direct path, defeating force-relay's privacy contract (security review
	// §1). With no advertised endpoint, peers route to us over the relay.
	if d.cfg.ForceRelay {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	eps := magicsock.GatherEndpoints(ctx, d.cfg.ListenPort, "")
	// Discover the mapping of WireGuard's own persistent socket. Put it first:
	// the engine currently programs one endpoint at a time, and a private RFC1918
	// candidate from another LAN is never reachable. Simultaneous keepalives from
	// both peers then create/refresh the NAT permissions needed for direct WG.
	var reflexive netip.AddrPort
	if discoverer, ok := d.engine.(wgengine.PublicEndpointDiscoverer); ok && d.cfg.STUNAddr != "" {
		if reflexive, err := discoverer.DiscoverPublicEndpoint(ctx, d.cfg.STUNAddr); err == nil && reflexive.IsValid() {
			d.mu.Lock()
			d.wgReflexive = reflexive
			d.mu.Unlock()
		} else if err != nil {
			d.log.Debug("WireGuard socket STUN discovery failed", "err", err)
		}
	}
	d.mu.Lock()
	reflexive = d.wgReflexive
	mapped := d.portMapping.External
	d.mu.Unlock()
	if reflexive.IsValid() {
		eps = append([]string{reflexive.String()}, eps...)
	}
	if mapped.IsValid() {
		eps = append([]string{mapped.String()}, eps...)
	}
	seen := map[string]bool{}
	for _, e := range eps {
		seen[e] = true
	}
	// Native mobile discovery candidates describe the provider's stable socket.
	// Prefer them to RFC1918 interface candidates when peers are on another NAT.
	var preferred []string
	for _, e := range d.cfg.ExtraEndpoints {
		if !seen[e] {
			preferred = append(preferred, e)
			seen[e] = true
		}
	}
	return append(preferred, eps...)
}

func (d *Daemon) refreshPortMapping(ctx context.Context) {
	mapping, err := magicsock.MapUDPPort(ctx, d.cfg.ListenPort)
	if err != nil {
		d.log.Debug("automatic UDP port mapping unavailable", "err", err)
		return
	}
	d.mu.Lock()
	changed := d.portMapping.External != mapping.External || d.portMapping.Protocol != mapping.Protocol
	d.portMapping = mapping
	d.mu.Unlock()
	if changed {
		d.log.Info("automatic UDP port mapping active", "protocol", mapping.Protocol, "endpoint", mapping.External, "lifetime", mapping.Lifetime)
	}
}

func (d *Daemon) portMappingLoop(ctx context.Context) {
	ticker := time.NewTicker(45 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		refreshCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		d.refreshPortMapping(refreshCtx)
		cancel()
	}
}

// discoPort is the UDP port used for the out-of-band disco reachability probe:
// one above the WireGuard ListenPort, so it never collides with the WG socket
// that kernel/wireguard-go owns (docs/relay-upgrade-probe.md). ok is false when
// ListenPort is 65535 (no room for +1 without wrapping to an invalid port 0).
func discoPort(listenPort uint16) (uint16, bool) {
	if listenPort == 65535 {
		return 0, false
	}
	return listenPort + 1, true
}

// discoEndpoints gathers this device's disco reachability candidates (a separate
// UDP port from WireGuard): the local interface addresses on the disco port, plus
// the STUN'd reflexive endpoint of the disco socket (set by startDiscoResponder)
// so peers can probe us through NAT, not only on-LAN. Off unless -disco-probe is
// set; empty under -force-relay (same privacy contract as localEndpoints). No
// consumer yet — the probe-gate that reads peers' disco endpoints is a later step.
func (d *Daemon) discoEndpoints() []string {
	if !d.cfg.EnableDiscoProbe || d.cfg.ForceRelay {
		return nil
	}
	dp, ok := discoPort(d.cfg.ListenPort)
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	eps := magicsock.GatherEndpoints(ctx, dp, "")
	// Append the STUN'd reflexive disco endpoint (set by startDiscoResponder) so
	// peers can probe us through NAT, not only on-LAN.
	d.mu.Lock()
	ref := d.discoReflexive
	d.mu.Unlock()
	if ref.IsValid() && !slices.Contains(eps, ref.String()) {
		eps = append(eps, ref.String())
	}
	return eps
}

// startDiscoResponder binds and serves a disco responder on the disco port
// (ListenPort+1) when the probe is enabled, so peers can confirm a direct path to
// us over a port that does NOT collide with the WG socket kernel/wireguard-go
// owns. Returns (nil, nil) when disabled. The responder stops on ctx and must be
// Closed by the caller. Distinct from the WG-port responder in Run (off under
// wgreal). No consumer yet — this only lets us answer probes.
func (d *Daemon) startDiscoResponder(ctx context.Context) (*magicsock.DiscoResponder, error) {
	// Suppressed under force-relay too (privacy contract): if we advertise no
	// disco endpoint, we should not answer probes on that port either.
	if !d.cfg.EnableDiscoProbe || d.cfg.ForceRelay {
		return nil, nil
	}
	dp, ok := discoPort(d.cfg.ListenPort)
	if !ok {
		return nil, nil
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(dp)})
	if err != nil {
		return nil, err
	}
	// STUN the disco socket BEFORE serving on it, so the reflexive mapping is for
	// THIS port (a separate ephemeral STUN socket would map a different one). The
	// result is advertised alongside the local disco endpoints.
	if d.cfg.STUNAddr != "" {
		sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		if ref, err := magicsock.STUNConn(sctx, conn, d.cfg.STUNAddr); err == nil {
			d.mu.Lock()
			d.discoReflexive = ref
			d.mu.Unlock()
			d.log.Info("disco reflexive endpoint discovered", "addr", ref)
		} else {
			d.log.Debug("disco STUN failed (advertising local disco endpoints only)", "err", err)
		}
		cancel()
	}
	resp := magicsock.NewDiscoResponder(conn)
	go resp.Serve(ctx)
	return resp, nil
}

func meshAddrsAsPrefixes(addrs []netip.Addr) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		bits := 32
		if a.Is6() {
			bits = 128
		}
		out = append(out, netip.PrefixFrom(a, bits))
	}
	return out
}

// StateDir returns the resolved state directory (exported for the local API).
func (d *Daemon) StateDir() string { return d.cfg.StateDir }

var _ = os.Getpid // reserved for future pidfile handling

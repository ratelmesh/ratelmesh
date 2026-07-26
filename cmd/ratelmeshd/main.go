// Command ratelmeshd is the RatelMesh client daemon (DESIGN.md §3.4): it holds the
// device identity, maintains the control-plane connection, drives the WireGuard
// data plane from the netmap, and serves a local API for the `ratelmesh` CLI/GUI.
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/ratelmesh/ratelmesh/internal/daemon"
	"github.com/ratelmesh/ratelmesh/internal/netguard"
	"github.com/ratelmesh/ratelmesh/internal/routing"
	"github.com/ratelmesh/ratelmesh/internal/sign"
	"github.com/ratelmesh/ratelmesh/internal/types"
	"github.com/ratelmesh/ratelmesh/internal/wgengine"
)

func main() {
	hostname, _ := os.Hostname()

	coordURL := flag.String("coord", envOr("RATELMESH_COORD", "http://127.0.0.1:8080"), "coord base URL")
	authKey := flag.String("authkey", os.Getenv("RATELMESH_AUTHKEY"), "auth key presented to coord")
	stateDir := flag.String("state", defaultStateDir(), "state directory")
	socket := flag.String("socket", "", "local API unix socket path (default: <state>/ratelmeshd.sock)")
	name := flag.String("hostname", hostname, "device name advertised to the mesh")
	port := flag.Uint("port", 0, "WireGuard listen port (0 = stable per-device port)")
	role := flag.String("role", "plain", "node role: plain | exit | subnet-router")
	routes := flag.String("advertise-routes", "", "comma-separated CIDRs to advertise (subnet-router)")
	tags := flag.String("tags", "", "comma-separated ACL tags for this device (e.g. tag:server)")
	stun := flag.String("stun", envOr("RATELMESH_STUN", "stun.cloudflare.com:3478"), "STUN server for public-endpoint discovery (host:port)")
	acceptRoutes := flag.Bool("accept-routes", false, "accept subnet routes advertised by subnet-router peers")
	enableNAT := flag.Bool("enable-nat", false, "exit node: forward + masquerade mesh traffic to the internet (Linux/macOS, root)")
	dnsAddr := flag.String("dns-addr", "", "bind the MagicDNS server on this address, e.g. 100.100.100.100:53")
	// A macOS full-tunnel route can leave the system resolver scoped to the
	// physical interface, causing DNS timeouts even while raw tunnel traffic is
	// healthy. Enable the local resolver by default there; callers can explicitly
	// opt out with -magic-dns=false.
	magicDNS := flag.Bool("magic-dns", runtime.GOOS == "darwin", "run MagicDNS on loopback and install it as the system resolver (mesh names + upstream forwarding)")
	splitRules := flag.String("split-tunnel", "", "path to a JSON split-tunnel ruleset (direct/tunnel/block by domain/CIDR/GeoIP)")
	killSwitch := flag.Bool("kill-switch", defaultKillSwitch(runtime.GOOS), "fail closed (block non-tunnel traffic) while an exit is active")
	tunnelDNS := flag.String("tunnel-dns", "", "UDP resolver host[:port] used while an exit is active (prevents DNS leaks; requires -magic-dns)")
	guiAddr := flag.String("gui", "", "serve the local web GUI on this loopback address, e.g. 127.0.0.1:8088")
	verifyKey := flag.String("verify-key", os.Getenv("RATELMESH_VERIFY_KEY"), "base64 key-authority public key; drop peers whose credential fails to verify (§5)")
	verifyPQKey := flag.String("verify-pq-key", os.Getenv("RATELMESH_VERIFY_PQ_KEY"), "base64 ML-DSA-65 authority public key; required with -verify-key")
	relayAddr := flag.String("relay", envOr("RATELMESH_RELAY", ""), "ratelmesh-relay address (host:port) for the fallback WireGuard transport when peers can't connect directly")
	discoProbe := flag.Bool("disco-probe", false, "advertise out-of-band disco endpoints for relay->direct upgrade probing (experimental, off by default)")
	forceRelay := flag.Bool("force-relay", false, "route all peer traffic through the relay (not just as a fallback)")
	coordTransport := flag.String("coord-transport", envOr("RATELMESH_COORD_TRANSPORT", ""), "carry the coordinator connection inside a camouflage transport (\"wss\") for censored networks; empty = plain HTTPS")
	coordFrontDoor := flag.String("coord-front-door", envOr("RATELMESH_COORD_FRONT_DOOR", ""), "host:port the -coord-transport dials (CDN edge / front door); default is the coordinator host on :443")
	flag.Parse()
	if !flagWasSet("tunnel-dns") {
		*tunnelDNS = defaultTunnelDNS(runtime.GOOS, *magicDNS)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if *port > 65535 {
		log.Error("-port must be between 0 and 65535", "port", *port)
		os.Exit(1)
	}
	// Role and role/flag cross-validation (-enable-nat, -advertise-routes,
	// Windows kill-switch × split-tunnel) happen in daemon.New so every client
	// surface (CLI, mobile binding) enforces the same rules.
	nodeRole := types.NodeRole(*role)
	effectiveKillSwitch := *killSwitch && nodeRole != types.RoleExit
	advertisedRoutes := splitCSV(*routes)
	requestedTags := splitCSV(*tags)
	if len(requestedTags) > 0 {
		log.Warn("client -tags are requests only; the coord accepts ACL tags solely from the enrolling authkey or identity provider", "tags", requestedTags)
	}

	var splitEngine *routing.Engine
	if *splitRules != "" {
		data, err := os.ReadFile(*splitRules)
		if err != nil {
			log.Error("read split-tunnel rules", "err", err)
			os.Exit(1)
		}
		splitEngine, err = routing.Parse(data)
		if err != nil {
			log.Error("parse split-tunnel rules", "err", err)
			os.Exit(1)
		}
		log.Info("split-tunnel enabled", "path", *splitRules,
			"direct", len(splitEngine.DirectPrefixes()), "block", len(splitEngine.BlockPrefixes()))
	}

	// --magic-dns is shorthand for a MagicDNS server on loopback that owns the
	// system resolver. Linux can use any 127/8 address; macOS and Windows use
	// 127.0.0.1 for compatibility with their native resolver integration.
	dnsBind := *dnsAddr
	manageResolv := false
	if *magicDNS {
		if dnsBind == "" {
			if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
				dnsBind = "127.0.0.1:53"
			} else {
				dnsBind = "127.0.0.53:53"
			}
		}
		manageResolv = true
	}

	// -tunnel-dns can only be enforced when a MagicDNS server is running to
	// redirect queries, and only supports a plain UDP resolver (host[:port]).
	// Reject configurations that would silently do nothing (security review §4).
	if *tunnelDNS != "" {
		if strings.HasPrefix(*tunnelDNS, "http://") || strings.HasPrefix(*tunnelDNS, "https://") {
			log.Error("-tunnel-dns must be a plain UDP resolver host[:port]; DoH URLs are not supported yet")
			os.Exit(1)
		}
		if dnsBind == "" {
			log.Error("-tunnel-dns requires -magic-dns (or -dns-addr) so a resolver can redirect DNS through the tunnel")
			os.Exit(1)
		}
	}

	var verifyPub ed25519.PublicKey
	var verifyPQPub *mldsa65.PublicKey
	if *verifyKey != "" {
		pub, err := sign.ParsePublicKey(*verifyKey)
		if err != nil {
			log.Error("parse -verify-key", "err", err)
			os.Exit(1)
		}
		verifyPub = pub
		log.Info("peer credential verification enabled")
	}
	if *verifyPQKey != "" {
		pub, err := sign.ParsePQPublicKey(*verifyPQKey)
		if err != nil {
			log.Error("parse -verify-pq-key", "err", err)
			os.Exit(1)
		}
		verifyPQPub = pub
	}
	if *verifyKey != "" && verifyPQPub == nil {
		// Rolling-upgrade compatibility: installed 0.1 launchd/Windows configs only
		// carry the Ed25519 authority key. The data plane still requires ML-KEM;
		// add the ML-DSA authority key before claiming post-quantum authentication.
		log.Warn("ML-DSA authority verification is not configured; add -verify-pq-key")
	}

	sockPath := *socket
	if sockPath == "" {
		sockPath = daemon.DefaultSocketPath()
	}

	d, err := daemon.New(daemon.Config{
		CoordURL:         *coordURL,
		AuthKey:          *authKey,
		StateDir:         *stateDir,
		Hostname:         *name,
		ListenPort:       uint16(*port),
		Role:             nodeRole,
		AdvertiseRoutes:  advertisedRoutes,
		Tags:             requestedTags,
		STUNAddr:         *stun,
		AcceptRoutes:     *acceptRoutes,
		EnableNAT:        *enableNAT,
		DNSAddr:          dnsBind,
		ManageResolv:     manageResolv,
		KillSwitch:       effectiveKillSwitch,
		TunnelDNS:        *tunnelDNS,
		RelayAddr:        *relayAddr,
		ForceRelay:       *forceRelay,
		EnableDiscoProbe: *discoProbe,
		CoordTransport:   *coordTransport,
		CoordFrontDoor:   *coordFrontDoor,
		Engine:           wgengine.New(log),
		Enforcer:         netguard.NewEnforcer(log),
		DisableDisco:     wgengine.OwnsListenPort(),
		SplitTunnel:      splitEngine,
		VerifyKey:        verifyPub,
		VerifyPQKey:      verifyPQPub,
		RequirePQC:       true,
		Logger:           log,
	})
	if err != nil {
		log.Error("init failed", "err", err)
		os.Exit(1)
	}

	log.Info("ratelmeshd starting", "pubkey", d.PublicKey().String(), "state", *stateDir, "socket", sockPath)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	api := daemon.NewLocalAPI(d, sockPath)
	go func() {
		if err := api.Serve(ctx); err != nil {
			log.Error("local API exited", "err", err)
		}
	}()
	if *guiAddr != "" {
		log.Info("web GUI enabled", "url", "http://"+*guiAddr)
		go func() {
			if err := api.ServeGUI(ctx, *guiAddr); err != nil {
				log.Error("GUI server exited", "err", err)
			}
		}()
	}

	if err := d.Run(ctx); err != nil && err != context.Canceled {
		log.Error("daemon exited", "err", err)
		os.Exit(1)
	}
}

func defaultKillSwitch(goos string) bool {
	// A macOS laptop can retain a working physical IPv6 route while its IPv4
	// default is carried by an exit. Defaulting to fail-closed there prevents
	// either address family from escaping during route loss, sleep or roaming.
	// Other platforms retain their existing opt-in behavior for compatibility.
	return goos == "darwin"
}

func defaultTunnelDNS(goos string, magicDNS bool) string {
	// macOS clients commonly retain an ISP/router resolver while using an exit.
	// Only select the leak-resistant default when the local MagicDNS resolver is
	// enabled; otherwise the documented -magic-dns=false opt-out must remain a
	// valid startup configuration.
	if goos == "darwin" && magicDNS {
		return "1.1.1.1:53"
	}
	return ""
}

func flagWasSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func defaultStateDir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "ratelmesh")
	}
	return filepath.Join(os.TempDir(), "ratelmesh")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

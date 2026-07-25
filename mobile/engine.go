package mobile

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/shan25519/ratelmesh/internal/types"
	"github.com/shan25519/ratelmesh/internal/wgengine"
)

// bindingEngine is the mobile data-plane boundary. The Go daemon owns control
// state and computes the desired WireGuard snapshot; the native iOS/Android
// tunnel provider polls the versioned JSON and applies it to the system VPN.
type bindingEngine struct {
	mu      sync.Mutex
	active  bool
	version uint64
	cfg     wgengine.Config
	dns     []string
	stats   map[types.Key]wgengine.PeerStat
}

type tunnelConfig struct {
	Version      uint64       `json:"version"`
	Active       bool         `json:"active"`
	PrivateKey   string       `json:"privateKey"`
	ListenPort   int          `json:"listenPort"`
	Addresses    []string     `json:"addresses"`
	DNSServers   []string     `json:"dnsServers"`
	KillSwitch   bool         `json:"killSwitch"`
	Peers        []tunnelPeer `json:"peers"`
	DirectRoutes []string     `json:"directRoutes"`
	BlockRoutes  []string     `json:"blockRoutes"`
}

type tunnelPeer struct {
	PublicKey           string   `json:"publicKey"`
	PresharedKey        string   `json:"presharedKey,omitempty"`
	Endpoint            string   `json:"endpoint"`
	AllowedIPs          []string `json:"allowedIPs"`
	PersistentKeepalive int      `json:"persistentKeepalive"`
}

func newBindingEngine(dns []string) *bindingEngine {
	return &bindingEngine{dns: append([]string(nil), dns...), stats: make(map[types.Key]wgengine.PeerStat)}
}

func (e *bindingEngine) Up() error {
	e.mu.Lock()
	e.active = true
	e.version++
	e.mu.Unlock()
	return nil
}

func (e *bindingEngine) Reconfigure(cfg wgengine.Config) error {
	e.mu.Lock()
	if mobileTunnelConfigEqual(e.cfg, cfg) {
		e.mu.Unlock()
		return nil
	}
	e.cfg = cloneEngineConfig(cfg)
	e.version++
	e.mu.Unlock()
	return nil
}

func mobileTunnelConfigEqual(prev, next wgengine.Config) bool {
	if prev.PrivateKey != next.PrivateKey || prev.ListenPort != next.ListenPort ||
		prev.KillSwitch != next.KillSwitch ||
		!slices.Equal(prev.Addresses, next.Addresses) ||
		!slices.Equal(prev.DNSServers, next.DNSServers) ||
		!slices.Equal(prev.DirectRoutes, next.DirectRoutes) ||
		!slices.Equal(prev.BlockRoutes, next.BlockRoutes) ||
		len(prev.Peers) != len(next.Peers) {
		return false
	}
	for i := range prev.Peers {
		a, b := prev.Peers[i], next.Peers[i]
		if a.PublicKey != b.PublicKey || a.PresharedKey != b.PresharedKey ||
			a.Keepalive != b.Keepalive ||
			!slices.Equal(a.Endpoints, b.Endpoints) ||
			!slices.Equal(a.AllowedIPs, b.AllowedIPs) {
			return false
		}
	}
	return true
}

func (e *bindingEngine) Peers() []types.Key {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]types.Key, 0, len(e.cfg.Peers))
	for _, peer := range e.cfg.Peers {
		out = append(out, peer.PublicKey)
	}
	return out
}

func (e *bindingEngine) Down() error {
	e.mu.Lock()
	if e.active {
		e.active = false
		e.version++
	}
	e.mu.Unlock()
	return nil
}

func (e *bindingEngine) Close() error { return e.Down() }

func (e *bindingEngine) PeerStats() (map[types.Key]wgengine.PeerStat, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[types.Key]wgengine.PeerStat, len(e.stats))
	for key, stat := range e.stats {
		out[key] = stat
	}
	return out, nil
}

type peerStatUpdate struct {
	PublicKey           string `json:"publicKey"`
	LatestHandshakeUnix int64  `json:"latestHandshakeUnix"`
	RxBytes             int64  `json:"rxBytes"`
}

func (e *bindingEngine) updateStatsJSON(raw string) error {
	var updates []peerStatUpdate
	if err := json.Unmarshal([]byte(raw), &updates); err != nil {
		return fmt.Errorf("mobile: parse peer stats: %w", err)
	}
	next := make(map[types.Key]wgengine.PeerStat, len(updates))
	for _, update := range updates {
		key, err := types.ParseKey(update.PublicKey)
		if err != nil {
			return fmt.Errorf("mobile: peer stats publicKey: %w", err)
		}
		stat := wgengine.PeerStat{RxBytes: update.RxBytes}
		if update.LatestHandshakeUnix > 0 {
			stat.LatestHandshake = time.Unix(update.LatestHandshakeUnix, 0)
		}
		next[key] = stat
	}
	e.mu.Lock()
	e.stats = next
	e.mu.Unlock()
	return nil
}

func (e *bindingEngine) configVersion() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return int64(e.version)
}

func (e *bindingEngine) configJSON() string {
	e.mu.Lock()
	snapshot := e.snapshotLocked()
	e.mu.Unlock()
	b, err := json.Marshal(snapshot)
	if err != nil {
		return `{"active":false}`
	}
	return string(b)
}

func (e *bindingEngine) snapshotLocked() tunnelConfig {
	out := tunnelConfig{
		Version: e.version, Active: e.active, KillSwitch: e.active && e.cfg.KillSwitch,
		Addresses: make([]string, 0), DNSServers: append([]string{}, e.dns...),
		Peers: make([]tunnelPeer, 0), DirectRoutes: make([]string, 0),
		BlockRoutes: make([]string, 0),
	}
	if !e.active {
		return out // never expose the device private key once the tunnel is down
	}
	out.PrivateKey = e.cfg.PrivateKey.String()
	out.ListenPort = int(e.cfg.ListenPort)
	for _, addr := range e.cfg.Addresses {
		out.Addresses = append(out.Addresses, addr.String())
	}
	for _, route := range e.cfg.DirectRoutes {
		out.DirectRoutes = append(out.DirectRoutes, route.String())
	}
	for _, route := range e.cfg.BlockRoutes {
		out.BlockRoutes = append(out.BlockRoutes, route.String())
	}
	for _, peer := range e.cfg.Peers {
		p := tunnelPeer{
			PublicKey:           peer.PublicKey.String(),
			AllowedIPs:          make([]string, 0),
			PersistentKeepalive: peer.Keepalive,
		}
		if !peer.PresharedKey.IsZero() {
			p.PresharedKey = peer.PresharedKey.String()
		}
		if len(peer.Endpoints) > 0 {
			p.Endpoint = peer.Endpoints[0]
		}
		for _, allowed := range peer.AllowedIPs {
			p.AllowedIPs = append(p.AllowedIPs, allowed.String())
		}
		out.Peers = append(out.Peers, p)
	}
	return out
}

func cloneEngineConfig(cfg wgengine.Config) wgengine.Config {
	out := cfg
	out.Addresses = append([]netip.Prefix(nil), cfg.Addresses...)
	out.DNSServers = append([]netip.Addr(nil), cfg.DNSServers...)
	out.DirectRoutes = append([]netip.Prefix(nil), cfg.DirectRoutes...)
	out.BlockRoutes = append([]netip.Prefix(nil), cfg.BlockRoutes...)
	out.Peers = make([]wgengine.Peer, len(cfg.Peers))
	for i, peer := range cfg.Peers {
		out.Peers[i] = peer
		out.Peers[i].Endpoints = append([]string(nil), peer.Endpoints...)
		out.Peers[i].AllowedIPs = append([]netip.Prefix(nil), peer.AllowedIPs...)
	}
	return out
}

package daemon

import (
	"net/netip"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/types"
)

// BackendState mirrors the daemon's lifecycle for the CLI/GUI.
type BackendState string

const (
	StateStopped  BackendState = "Stopped"
	StateStarting BackendState = "Starting"
	StateRunning  BackendState = "Running"
)

// Status is the snapshot the local API returns to `ratelmesh status`. It is the
// stable contract between ratelmeshd and its front-ends (CLI now, GUI later).
type Status struct {
	State              BackendState `json:"state"`
	CoordURL           string       `json:"coordURL"`
	Version            uint64       `json:"netmapVersion"`
	Self               PeerStatus   `json:"self"`
	Peers              []PeerStatus `json:"peers"`
	EnrollmentRequired bool         `json:"enrollmentRequired"`
	// ActiveExit is the name of the exit node currently carrying egress traffic,
	// or "" for direct egress (DESIGN.md §3.3).
	ActiveExit string `json:"activeExit"`
	// SelectedExit is the requested exit node while its data path is being
	// established. It may be non-empty while ActiveExit is still empty; frontends
	// must show that as connecting, never as active EXIT routing.
	SelectedExit string `json:"selectedExit,omitempty"`
	// ExitTrafficVerified is true only after the default routes were installed
	// and encrypted receive bytes subsequently advanced on that exit peer. A
	// handshake or a user selection alone is not reported as successful traffic.
	ExitTrafficVerified bool `json:"exitTrafficVerified"`
	// KillSwitch reports whether fail-closed firewalling is armed (§3.3).
	KillSwitch bool `json:"killSwitch"`
	// InternetFallback trades leak protection for availability: the daemon keeps
	// the host usable through its physical connection when an exit fails.
	InternetFallback bool `json:"internetFallback"`
	// DNS is the effective resolver ("system" or the tunnel DoH endpoint).
	DNS string `json:"dns"`
	// ExitClients lists authenticated visible peers that selected this device as
	// their EXIT. State is "active" only after that client locally verified its
	// handshake/data-path gate; "connecting" is merely a requested selection.
	ExitClients []ExitClientStatus `json:"exitClients,omitempty"`
}

type ExitClientStatus struct {
	Name     string    `json:"name"`
	MeshIP   string    `json:"meshIP"`
	State    string    `json:"state"`
	Online   bool      `json:"online"`
	LastSeen time.Time `json:"lastSeen"`
}

// PeerStatus is one device as shown to the user.
type PeerStatus struct {
	Name                string         `json:"name"`
	MeshIP              string         `json:"meshIP"`
	KeyShort            string         `json:"keyShort"`
	Role                types.NodeRole `json:"role"`
	Platform            string         `json:"platform,omitempty"`
	RemoteAccessAllowed bool           `json:"remoteAccessAllowed,omitempty"`
	Online              bool           `json:"online"`
	// PathType is "direct", "relay" or "-" (unknown/M1). Populated by magicsock
	// in M2 (DESIGN.md §3.2).
	PathType string `json:"pathType"`
}

func peerStatusFromNode(n types.Node) PeerStatus {
	return PeerStatus{
		Name:                n.Name,
		MeshIP:              firstAddr(n.MeshIPs),
		KeyShort:            n.Key.ShortString(),
		Role:                n.Role,
		Platform:            n.Platform,
		RemoteAccessAllowed: n.RemoteAccessAllowed,
		Online:              n.Online,
		PathType:            "-",
	}
}

func exitClientStatus(selfID string, peer types.Node) (ExitClientStatus, bool) {
	if selfID == "" || peer.SelectedExitID != selfID {
		return ExitClientStatus{}, false
	}
	state := "connecting"
	if peer.ActiveExitID == selfID && peer.Online {
		state = "active"
	} else if !peer.Online {
		state = "offline"
	}
	return ExitClientStatus{
		Name: peer.Name, MeshIP: firstAddr(peer.MeshIPs), State: state,
		Online: peer.Online, LastSeen: peer.LastSeen,
	}, true
}

func firstAddr(addrs []netip.Addr) string {
	if len(addrs) == 0 {
		return ""
	}
	return addrs[0].String()
}

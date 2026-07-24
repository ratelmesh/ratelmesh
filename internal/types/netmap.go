package types

import (
	"net/netip"
	"time"
)

// NodeRole distinguishes the kinds of node in a mesh. A plain node only routes
// its own mesh address; an exit node advertises a default route; a subnet
// router advertises one or more CIDRs. See DESIGN.md §3.3 and §10.2.
type NodeRole string

const (
	RolePlain        NodeRole = "plain"
	RoleExit         NodeRole = "exit"
	RoleSubnetRouter NodeRole = "subnet-router"
)

// NodeCapabilities are server-authoritative services this enrolled member may
// provide. Every Node is already a normal mesh member; Exit and Relay are
// independent optional capabilities and may be enabled together.
type NodeCapabilities struct {
	Exit  bool `json:"exit"`
	Relay bool `json:"relay"`
}

// Node is one device in the mesh as seen by the control plane. The subset that
// a given client receives is the netmap; ACL-hidden peers never appear (server
// -side trimming, DESIGN.md §3.1).
type Node struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	User string `json:"user"`
	// Platform is the client-reported operating-system family.
	Platform string `json:"platform,omitempty"`
	// LocationRegion is a coarse administrative region. LocationSource records
	// whether it came from a manual override, authorized system location, or the
	// coordinator's public-IP fallback. Exact coordinates and public IPs are not
	// retained in the node record.
	LocationRegion string `json:"locationRegion,omitempty"`
	LocationSource string `json:"locationSource,omitempty"`
	// RemoteAccessAllowed is a coordinator-computed presentation grant. It lets
	// official clients expose safe protocol launchers for this target; clients
	// never submit or persist this value and it grants no routing capability.
	RemoteAccessAllowed bool `json:"remoteAccessAllowed,omitempty"`
	Key                 Key  `json:"key"` // public key
	// PQKEMPublicKey is this node's ML-KEM-768 encapsulation key. PQSigningPublicKey
	// authenticates pairwise encapsulations so the coordinator cannot substitute
	// a ciphertext whose shared secret it knows.
	PQKEMPublicKey     []byte       `json:"pqKemPublicKey,omitempty"`
	PQSigningPublicKey []byte       `json:"pqSigningPublicKey,omitempty"`
	MeshIPs            []netip.Addr `json:"meshIPs"`   // assigned 100.64/10 (+ ULA v6 later)
	Endpoints          []string     `json:"endpoints"` // ip:port candidates for hole-punching
	// DiscoEndpoints are ip:port candidates for the out-of-band disco reachability
	// probe (a separate UDP port from WireGuard), used to gate relay→direct upgrade
	// without disturbing the data path (docs/relay-upgrade-probe.md). Volatile like
	// Endpoints; excluded from the authority signature.
	DiscoEndpoints []string         `json:"discoEndpoints,omitempty"`
	AllowedIPs     []string         `json:"allowedIPs"` // CIDRs this peer is authoritative for
	Role           NodeRole         `json:"role"`
	Capabilities   NodeCapabilities `json:"capabilities"`
	Tags           []string         `json:"tags"` // e.g. tag:laptop, tag:server
	Online         bool             `json:"online"`
	LastSeen       time.Time        `json:"lastSeen"`
	// SelectedExitID/ActiveExitID are authenticated runtime telemetry from this
	// node. They let an exit device show which visible peers selected it and
	// which have proved a live data path. They do not participate in routing.
	SelectedExitID string `json:"selectedExitID,omitempty"`
	ActiveExitID   string `json:"activeExitID,omitempty"`
	// Sig is the key authority's signature over this node's identity→key binding
	// (DESIGN.md §5). Clients verify it before trusting the peer; empty if the
	// coord runs without an authority key.
	Sig []byte `json:"sig,omitempty"`
	// RouteSig binds the identity, key and authoritative AllowedIPs. It is kept
	// separate from Sig so upgraded coordinators remain compatible with older
	// clients while upgraded clients reject route-tampered netmaps.
	RouteSig []byte `json:"routeSig,omitempty"`
	// PQSig/PQRouteSig are ML-DSA-65 counterparts to the Ed25519 credentials.
	// Strict clients require both signatures, preserving classical security while
	// adding post-quantum authentication.
	PQSig      []byte `json:"pqSig,omitempty"`
	PQRouteSig []byte `json:"pqRouteSig,omitempty"`
}

// Netmap is the view of the mesh delivered to a single node: itself plus the
// peers it is allowed to reach. DERPMap/relay info and DNS records attach here
// in later milestones.
type Netmap struct {
	// Version increases every time the map changes; clients long-poll with the
	// version they last saw so the coord can block until there is something new.
	Version uint64 `json:"version"`
	Self    Node   `json:"self"`
	Peers   []Node `json:"peers"`
	// PQSessions contains only sessions involving Self and an ACL-visible peer.
	// The coordinator stores ciphertext and signatures but never learns a PSK.
	PQSessions []PQSession `json:"pqSessions,omitempty"`
	// Relays are ratelmesh-relay addresses (host:port) the coord advertises for the
	// fallback WireGuard transport, so clients don't need a manual -relay flag
	// (DESIGN.md §3.2, DERP-style relay map).
	Relays []string `json:"relays,omitempty"`
}

// PQSession is an ML-KEM-768 encapsulation from the lexicographically smaller
// node ID to the larger node ID. Signature is ML-DSA-65 over both IDs and the
// ciphertext, preventing coordinator substitution and cross-pair replay.
type PQSession struct {
	InitiatorID string `json:"initiatorID"`
	RecipientID string `json:"recipientID"`
	Ciphertext  []byte `json:"ciphertext"`
	Signature   []byte `json:"signature"`
}

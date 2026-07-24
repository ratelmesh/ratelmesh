package types

// Control-plane API contract (M1: HTTP+JSON long-poll; migrates to gRPC
// streaming in M2, DESIGN.md §3.1). Kept in the shared types package so coord,
// ratelmeshd and tests all agree on one definition.

// RegisterRequest is sent by ratelmeshd when a device first joins or re-announces.
type RegisterRequest struct {
	// AuthKey authenticates the device to a tenant. M1 accepts a static
	// pre-shared key; OIDC/authkey issuance lands in M4 (DESIGN.md §10.3).
	AuthKey string `json:"authKey"`
	// NodeKey is the device's WireGuard public key. The private half never
	// leaves the device.
	NodeKey            Key    `json:"nodeKey"`
	PQKEMPublicKey     []byte `json:"pqKemPublicKey,omitempty"`
	PQSigningPublicKey []byte `json:"pqSigningPublicKey,omitempty"`
	// Hostname is a human-friendly device name (may be adjusted for uniqueness).
	Hostname string `json:"hostname"`
	// MachineIdentity is an unlinkable hash of the physical machine identity and
	// NodeKey. The coordinator binds it on first sight and rejects later use of
	// the same node key from another machine. The raw hardware identifier never
	// leaves the device.
	MachineIdentity string `json:"machineIdentity,omitempty"`
	// BindMachineIdentity is set only by the coordinator after a fresh
	// enrollment credential is authenticated. It is never accepted from JSON.
	BindMachineIdentity bool `json:"-"`
	// Platform is the operating-system family reported by the client. It is
	// informational only and never grants capabilities.
	Platform string `json:"platform,omitempty"`
	// LocationRegion is a coarse region derived locally from an authorized
	// system-location reading. Exact coordinates never leave the device.
	LocationRegion string `json:"locationRegion,omitempty"`
	// LocationSource is assigned by the coordinator after validating the
	// request context; clients cannot select it on the wire.
	LocationSource string `json:"-"`
	// Endpoints are locally-discovered ip:port candidates (STUN results in M2).
	Endpoints []string `json:"endpoints"`
	// DiscoEndpoints are locally-discovered ip:port candidates for the out-of-band
	// disco reachability probe (separate UDP port from WireGuard).
	DiscoEndpoints []string `json:"discoEndpoints,omitempty"`
	// Role/AdvertiseRoutes let a node announce exit / subnet-router capability.
	Role            NodeRole `json:"role"`
	AdvertiseRoutes []string `json:"advertiseRoutes"`
	// Capabilities is populated only by the authenticated control-plane path.
	// Client JSON cannot grant itself Exit or Relay authority.
	Capabilities NodeCapabilities `json:"-"`
	// Tags are ACL labels the device requests. They are IGNORED by the coord —
	// only authenticator-granted tags are trusted — but kept for wire compat.
	Tags []string `json:"tags"`
	// SessionToken proves ownership of an already-registered NodeKey (issued on
	// first registration). Empty on first registration (security review §1).
	SessionToken string `json:"sessionToken"`
	// User is set SERVER-SIDE from the authenticated identity (e.g. an OIDC
	// subject/email); any client-supplied value is ignored. It becomes Node.User,
	// which the default same-user ACL policy keys on (security review §2).
	User string `json:"-"`
	// Proof is the X25519 proof-of-possession over the coord's public key,
	// proving the device holds NodeKey's private half (security review §1/§4).
	Proof []byte `json:"proof,omitempty"`
	// ProofTime is the Unix timestamp bound into Proof (freshness/replay window).
	ProofTime int64 `json:"proofTime,omitempty"`
	// ProofNonce is the coordinator-issued, single-use challenge bound into Proof.
	ProofNonce string `json:"proofNonce,omitempty"`
}

// CoordKeyResponse carries the coord's X25519 public key (base64) for clients to
// build their proof-of-possession. Served unauthenticated at GET /v1/coordkey.
type CoordKeyResponse struct {
	PublicKey string `json:"publicKey"`
	Nonce     string `json:"nonce"`
}

// RegisterResponse tells the device who it now is in the mesh.
type RegisterResponse struct {
	NodeID string `json:"nodeID"`
	Netmap Netmap `json:"netmap"`
	// SessionToken must be presented on subsequent polls and re-registrations to
	// prove this device owns the node.
	SessionToken string `json:"sessionToken"`
}

// PollRequest is the long-poll for netmap updates. The coord holds the request
// open until Version differs from KnownVersion (or a timeout elapses).
type PollRequest struct {
	NodeID          string `json:"nodeID"`
	AuthKey         string `json:"authKey"`
	MachineIdentity string `json:"machineIdentity,omitempty"`
	KnownVersion    uint64 `json:"knownVersion"`
	Platform        string `json:"platform,omitempty"`
	// LocationRegion refreshes the last authorized system-location region. An
	// empty value means unavailable/unauthorized and lets the coordinator use
	// its public-IP fallback.
	LocationRegion string `json:"locationRegion,omitempty"`
	LocationSource string `json:"-"`
	// Endpoints refreshes the device's candidate list on each poll.
	Endpoints []string `json:"endpoints"`
	// DiscoEndpoints refreshes the device's disco probe candidates on each poll
	// (same volatility contract as RegisterRequest.DiscoEndpoints). omitempty:
	// nil/empty is absent on the wire and leaves the stored value unchanged, so
	// probe-off daemons and older clients stay wire-identical; an explicit clear
	// happens on re-registration, whose Upsert overwrites unconditionally.
	DiscoEndpoints []string `json:"discoEndpoints,omitempty"`
	// SelectedExitID and ActiveExitID report this authenticated device's local
	// routing state. The coordinator validates that both refer to visible,
	// exit-capable peers; they are telemetry only and never grant routes.
	SelectedExitID string `json:"selectedExitID,omitempty"`
	ActiveExitID   string `json:"activeExitID,omitempty"`
	// SessionToken proves this caller owns NodeID (security review §1).
	SessionToken string `json:"sessionToken"`
}

// PollResponse carries a fresh netmap (Changed=true) or signals a timeout with
// no change (Changed=false), in which case the client simply polls again.
type PollResponse struct {
	Changed bool   `json:"changed"`
	Netmap  Netmap `json:"netmap"`
	// SessionToken is a refreshed token; the client replaces its stored token so
	// a long-lived device never hits the TTL (security review §3).
	SessionToken string `json:"sessionToken,omitempty"`
}

// PQSessionRequest publishes an end-to-end authenticated ML-KEM encapsulation.
// Only InitiatorID may submit it and it must be the canonical smaller node ID.
type PQSessionRequest struct {
	NodeID          string `json:"nodeID"`
	PeerID          string `json:"peerID"`
	SessionToken    string `json:"sessionToken"`
	MachineIdentity string `json:"machineIdentity,omitempty"`
	Ciphertext      []byte `json:"ciphertext"`
	Signature       []byte `json:"signature"`
}

// ErrorResponse is the JSON body for any non-2xx control-plane reply. Code is a
// stable machine string; ratelmeshd maps it to a localized message (DESIGN.md §9.3).
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

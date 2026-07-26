// Package control is the client half of the coord protocol used by ratelmeshd: device
// registration and long-poll netmap updates over HTTP/JSON (M1). It migrates to
// gRPC streaming in M2 (DESIGN.md §3.1) behind this same interface.
package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/pop"
	"github.com/ratelmesh/ratelmesh/internal/pqcrypto"
	"github.com/ratelmesh/ratelmesh/internal/remoteaccess"
	"github.com/ratelmesh/ratelmesh/internal/types"
)

const maxSessionTokenBytes = 1024

// Client talks to a single coord server.
type Client struct {
	baseURL string
	authKey string
	hc      *http.Client

	mu              sync.Mutex
	token           string    // session token proving node ownership (security review §1)
	nodePriv        types.Key // node private key, for proof-of-possession on register
	machineIdentity string
	nextRequestID   uint64
	inflight        map[uint64]context.CancelFunc
}

// SetNodeKey sets the device private key used to build the registration
// proof-of-possession (security review §1/§4).
func (c *Client) SetNodeKey(priv types.Key) {
	c.mu.Lock()
	c.nodePriv = priv
	c.mu.Unlock()
}

// SetMachineIdentity adds the physical-machine binding to every authenticated
// control request. Keeping it in Client prevents a copied session token from
// bypassing registration and polling directly.
func (c *Client) SetMachineIdentity(identity string) {
	c.mu.Lock()
	c.machineIdentity = identity
	c.mu.Unlock()
}

// NewClient builds a coord client. The http.Client timeout is generous because
// poll requests block server-side for up to the coord's long-poll window.
func NewClient(baseURL, authKey string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		authKey: authKey,
		hc: &http.Client{
			Timeout:   60 * time.Second,
			Transport: pqcrypto.HTTPTransport(),
		},
		inflight: make(map[uint64]context.CancelFunc),
	}
}

// ResetNetwork cancels control requests that may still be bound to a vanished
// physical interface and drops pooled connections. The next registration then
// performs a fresh DNS lookup and TCP/TLS handshake on the current route.
func (c *Client) ResetNetwork() {
	c.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(c.inflight))
	for _, cancel := range c.inflight {
		cancels = append(cancels, cancel)
	}
	c.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	c.hc.CloseIdleConnections()
}

func (c *Client) requestContext(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	c.mu.Lock()
	c.nextRequestID++
	id := c.nextRequestID
	c.inflight[id] = cancel
	c.mu.Unlock()
	return ctx, func() {
		cancel()
		c.mu.Lock()
		delete(c.inflight, id)
		c.mu.Unlock()
	}
}

// SetToken sets the persisted session token (loaded from state at startup).
func (c *Client) SetToken(t string) {
	c.mu.Lock()
	c.token = t
	c.mu.Unlock()
}

// Token returns the current session token (for the daemon to persist).
func (c *Client) Token() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

// Register announces this device and returns its assigned identity + netmap. It
// attaches an X25519 proof-of-possession over the coord's public key, proving
// this device holds the node private key (security review §1/§4).
func (c *Client) Register(ctx context.Context, req types.RegisterRequest) (*types.RegisterResponse, error) {
	req.AuthKey = c.authKey
	req.SessionToken = c.Token()

	coordPub, nonce, proofVersion, err := c.coordKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch coord key: %w", err)
	}
	c.mu.Lock()
	priv := c.nodePriv
	machineIdentity := c.machineIdentity
	c.mu.Unlock()
	if req.MachineIdentity == "" {
		req.MachineIdentity = machineIdentity
	}
	req.ProofTime = time.Now().Unix()
	req.ProofNonce = nonce
	req.ProofVersion = proofVersion
	proofContext := pop.Context(req.ProofTime, priv.Public(), string(req.Role), req.AdvertiseRoutes)
	if nonce != "" {
		if proofVersion >= 2 {
			proofContext = pop.ChallengeContextV2(req.ProofTime, nonce, priv.Public(), string(req.Role), req.AdvertiseRoutes, req.Endpoints, req.DiscoEndpoints, req.MachineIdentity, req.PQKEMPublicKey, req.PQSigningPublicKey)
		} else {
			proofContext = pop.ChallengeContext(req.ProofTime, nonce, priv.Public(), string(req.Role), req.AdvertiseRoutes, req.Endpoints, req.DiscoEndpoints, req.PQKEMPublicKey, req.PQSigningPublicKey)
		}
	}
	proof, err := pop.Prove(priv, coordPub, proofContext)
	if err != nil {
		return nil, err
	}
	req.Proof = proof

	var resp types.RegisterResponse
	if err := c.post(ctx, "/v1/register", req, &resp); err != nil {
		return nil, err
	}
	if err := c.validateNetmapBinding(resp.NodeID, resp.Netmap); err != nil {
		return nil, fmt.Errorf("register response identity: %w", err)
	}
	if err := validateSessionToken(resp.SessionToken); err != nil {
		return nil, fmt.Errorf("register response token: %w", err)
	}
	if resp.SessionToken != "" {
		c.SetToken(resp.SessionToken)
	}
	return &resp, nil
}

// coordKey fetches the coord's X25519 public key and a fresh one-shot challenge.
func (c *Client) coordKey(ctx context.Context) ([32]byte, string, int, error) {
	ctx, done := c.requestContext(ctx)
	defer done()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/coordkey", nil)
	if err != nil {
		return [32]byte{}, "", 0, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return [32]byte{}, "", 0, err
	}
	defer resp.Body.Close()
	data, err := readLimitedResponse(resp.Body)
	if err != nil {
		return [32]byte{}, "", 0, err
	}
	if resp.StatusCode/100 != 2 {
		return [32]byte{}, "", 0, fmt.Errorf("coord /v1/coordkey: status %d", resp.StatusCode)
	}
	var kr types.CoordKeyResponse
	if err := json.Unmarshal(data, &kr); err != nil {
		return [32]byte{}, "", 0, err
	}
	raw, err := base64.StdEncoding.DecodeString(kr.PublicKey)
	if err != nil || len(raw) != 32 {
		return [32]byte{}, "", 0, fmt.Errorf("bad coord key")
	}
	var pub [32]byte
	copy(pub[:], raw)
	return pub, kr.Nonce, kr.ProofVersion, nil
}

// Poll performs one long-poll for netmap changes since knownVersion.
func (c *Client) Poll(ctx context.Context, nodeID string, knownVersion uint64, endpoints, discoEndpoints []string) (*types.PollResponse, error) {
	return c.PollWithMetadata(ctx, nodeID, knownVersion, endpoints, discoEndpoints, "", "")
}

// PollWithMetadata refreshes liveness plus informational device metadata.
func (c *Client) PollWithMetadata(ctx context.Context, nodeID string, knownVersion uint64, endpoints, discoEndpoints []string, platform, locationRegion string) (*types.PollResponse, error) {
	return c.PollWithRuntime(ctx, nodeID, knownVersion, endpoints, discoEndpoints, platform, locationRegion, "", "")
}

// PollWithRuntime refreshes liveness, device metadata and authenticated local
// EXIT state. Exit IDs are validated by the coordinator and remain telemetry;
// they cannot change server-authoritative capabilities or routes.
func (c *Client) PollWithRuntime(ctx context.Context, nodeID string, knownVersion uint64, endpoints, discoEndpoints []string, platform, locationRegion, selectedExitID, activeExitID string) (*types.PollResponse, error) {
	return c.PollWithRuntimeAndServices(ctx, nodeID, knownVersion, endpoints, discoEndpoints, platform, locationRegion, selectedExitID, activeExitID, nil)
}

// PollWithRuntimeAndServices additionally refreshes target-side remote-service
// observations. A nil service slice preserves the previous observation after a
// transient detector failure; a non-nil empty slice explicitly clears it.
func (c *Client) PollWithRuntimeAndServices(ctx context.Context, nodeID string, knownVersion uint64, endpoints, discoEndpoints []string, platform, locationRegion, selectedExitID, activeExitID string, remoteServices []remoteaccess.ServiceAdvertisement) (*types.PollResponse, error) {
	c.mu.Lock()
	machineIdentity := c.machineIdentity
	c.mu.Unlock()
	req := types.PollRequest{
		NodeID:          nodeID,
		KnownVersion:    knownVersion,
		Endpoints:       endpoints,
		DiscoEndpoints:  discoEndpoints,
		Platform:        platform,
		LocationRegion:  locationRegion,
		SelectedExitID:  selectedExitID,
		ActiveExitID:    activeExitID,
		RemoteServices:  remoteServices,
		SessionToken:    c.Token(),
		MachineIdentity: machineIdentity,
	}
	var resp types.PollResponse
	if err := c.post(ctx, "/v1/poll", req, &resp); err != nil {
		return nil, err
	}
	if resp.Changed {
		if err := c.validateNetmapBinding(nodeID, resp.Netmap); err != nil {
			return nil, fmt.Errorf("poll response identity: %w", err)
		}
	}
	if err := validateSessionToken(resp.SessionToken); err != nil {
		return nil, fmt.Errorf("poll response token: %w", err)
	}
	if resp.SessionToken != "" {
		c.SetToken(resp.SessionToken) // token refreshed by the coord (§3)
	}
	return &resp, nil
}

func (c *Client) validateNetmapBinding(nodeID string, nm types.Netmap) error {
	if nodeID == "" || nm.Self.ID != nodeID {
		return fmt.Errorf("netmap self ID %q does not match node ID %q", nm.Self.ID, nodeID)
	}
	c.mu.Lock()
	priv := c.nodePriv
	c.mu.Unlock()
	if priv == (types.Key{}) {
		return fmt.Errorf("device identity key is not configured")
	}
	if nm.Self.Key != priv.Public() {
		return fmt.Errorf("netmap self key does not match device identity")
	}
	if nm.Version == 0 {
		return fmt.Errorf("netmap version is zero")
	}
	return nil
}

func validateSessionToken(token string) error {
	if len(token) > maxSessionTokenBytes {
		return fmt.Errorf("session token exceeds %d bytes", maxSessionTokenBytes)
	}
	return nil
}

// PublishPQSession sends an ML-KEM ciphertext and its device ML-DSA signature
// to the coordinator. The coordinator can route and persist it but cannot derive
// the resulting WireGuard PSK.
func (c *Client) PublishPQSession(ctx context.Context, nodeID, peerID string, epoch uint64, ciphertext, signature []byte) error {
	c.mu.Lock()
	machineIdentity := c.machineIdentity
	c.mu.Unlock()
	req := types.PQSessionRequest{
		NodeID: nodeID, PeerID: peerID, SessionToken: c.Token(),
		MachineIdentity: machineIdentity, Epoch: epoch, Ciphertext: ciphertext, Signature: signature,
	}
	return c.post(ctx, "/v1/pqsession", req, nil)
}

func (c *Client) post(ctx context.Context, path string, in, out any) error {
	ctx, done := c.requestContext(ctx)
	defer done()
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.hc.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()

	data, err := readLimitedResponse(httpResp.Body)
	if err != nil {
		return err
	}
	if httpResp.StatusCode/100 != 2 {
		var e types.ErrorResponse
		if json.Unmarshal(data, &e) == nil && e.Code != "" {
			return &APIError{Status: httpResp.StatusCode, Code: e.Code, Message: e.Message}
		}
		return fmt.Errorf("coord %s: status %d", path, httpResp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

const maxResponseBody = 8 << 20

func readLimitedResponse(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxResponseBody+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseBody {
		return nil, fmt.Errorf("coord response exceeds %d bytes", maxResponseBody)
	}
	return data, nil
}

// APIError is a structured coord error, carrying the stable Code that ratelmeshd maps
// to a localized message (DESIGN.md §9.3).
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("coord error %s (%d): %s", e.Code, e.Status, e.Message)
}

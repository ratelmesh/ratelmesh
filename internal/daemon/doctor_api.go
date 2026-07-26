package daemon

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/diagnose"
	"github.com/ratelmesh/ratelmesh/internal/doctorplatform"
	"github.com/ratelmesh/ratelmesh/internal/types"
	"github.com/ratelmesh/ratelmesh/internal/wgengine"
)

type NetworkDoctorResult struct {
	Schema            string                          `json:"schema"`
	Report            diagnose.Report                 `json:"report"`
	Plan              diagnose.RepairPlan             `json:"plan"`
	AvailableRepairs  []diagnose.RepairActionID       `json:"availableRepairs,omitempty"`
	ObservationErrors []NetworkDoctorObservationError `json:"observationErrors,omitempty"`
	PlanID            string                          `json:"planID,omitempty"`
	PlanExpiresAt     string                          `json:"planExpiresAt,omitempty"`
}

// NetworkDoctorObservationError is the stable, identifier-only wire shape.
// Keeping it separate from doctorplatform prevents Go field names or future
// collector details from silently changing the native-client JSON contract.
type NetworkDoctorObservationError struct {
	Observation string `json:"observation"`
	Kind        string `json:"kind"`
}

type NetworkDoctorExecution struct {
	Schema    string                   `json:"schema"`
	Execution diagnose.ExecutionReport `json:"execution"`
}

const (
	doctorDisclosureVersion = "v1"
	doctorAPISchema         = "ratelmesh.doctor.api/v1"
	doctorExecutionSchema   = "ratelmesh.doctor.execution/v1"
	doctorPlanTTL           = 5 * time.Minute
	maxDoctorJSONBytes      = 1 << 20
	doctorTokenBytes        = 32
)

var (
	ErrDoctorInvalidRequest      = errors.New("doctor.invalid_request")
	ErrDoctorDisclosureRequired  = errors.New("doctor.disclosure_required")
	ErrDoctorBusy                = errors.New("doctor.busy")
	ErrDoctorRepairUnsupported   = errors.New("doctor.repair_unsupported")
	ErrDoctorPlanRequired        = errors.New("doctor.plan_required")
	ErrDoctorPlanExpired         = errors.New("doctor.plan_expired")
	ErrDoctorPlanMismatch        = errors.New("doctor.plan_mismatch")
	ErrDoctorRepairNotApplicable = errors.New("doctor.repair_not_applicable")
	ErrDoctorResponseTooLarge    = errors.New("doctor.response_too_large")
	ErrDoctorUnavailable         = errors.New("doctor.unavailable")
)

// DoctorDisclosureVersion is the consent text version native clients must show
// before an active diagnostic or repair request.
func DoctorDisclosureVersion() string { return doctorDisclosureVersion }

type doctorPlanAuthorization struct {
	digest    [sha256.Size]byte
	actions   map[diagnose.RepairActionID]struct{}
	expiresAt time.Time
	runCtx    context.Context
}

// NetworkDoctor is the bounded daemon/mobile API state machine. One instance is
// shared per Daemon so local HTTP and native mobile callers cannot run probes or
// privileged repairs concurrently.
type NetworkDoctor struct {
	d      *Daemon
	run    chan struct{}
	mu     sync.Mutex
	plan   doctorPlanAuthorization
	now    func() time.Time
	random io.Reader
}

func newNetworkDoctor(d *Daemon) *NetworkDoctor {
	return &NetworkDoctor{
		d: d, run: make(chan struct{}, 1),
		now: time.Now, random: rand.Reader,
	}
}

func (d *Daemon) networkDoctor() *NetworkDoctor {
	if d == nil {
		return nil
	}
	d.doctorOnce.Do(func() { d.doctor = newNetworkDoctor(d) })
	return d.doctor
}

// NetworkDoctor returns the shared diagnosis/repair state machine for trusted
// in-process clients such as the gomobile binding.
func (d *Daemon) NetworkDoctor() *NetworkDoctor { return d.networkDoctor() }

func (n *NetworkDoctor) acquire() bool {
	if n == nil {
		return false
	}
	select {
	case n.run <- struct{}{}:
		return true
	default:
		return false
	}
}

func (n *NetworkDoctor) release() { <-n.run }

type doctorRunRequest struct {
	Confirm           bool   `json:"confirm"`
	DisclosureVersion string `json:"disclosureVersion"`
}

type doctorRepairRequest struct {
	Action            diagnose.RepairActionID `json:"action"`
	PlanID            string                  `json:"planID"`
	Confirm           bool                    `json:"confirm"`
	DisclosureVersion string                  `json:"disclosureVersion"`
}

// defaultDoctorMediaTargets must contain only bounded, RatelMesh-operated
// canaries. An active probe reveals the diagnostic time and the current
// source/EXIT address to the operator, so silently using an unrelated
// third-party CDN is outside the product privacy boundary.
func defaultDoctorMediaTargets() []diagnose.Endpoint {
	return []diagnose.Endpoint{{
		Label:          "ratelmesh-media-canary",
		Host:           "ratelmesh.com",
		Port:           443,
		Scheme:         "https",
		HealthPath:     "/og.png",
		EvidenceSource: "ratelmesh-web-cdn",
	}}
}

func (a *LocalAPI) handleDoctor(w http.ResponseWriter, r *http.Request) {
	var input doctorRunRequest
	if err := decodeStrictJSON(r.Body, 4<<10, &input); err != nil {
		writeDoctorError(w, ErrDoctorInvalidRequest)
		return
	}
	if !input.Confirm || input.DisclosureVersion != doctorDisclosureVersion {
		writeDoctorError(w, ErrDoctorDisclosureRequired)
		return
	}
	if a.d == nil {
		writeDoctorError(w, ErrDoctorInvalidRequest)
		return
	}
	response, err := a.d.networkDoctor().Run(r.Context(), input.Confirm, input.DisclosureVersion)
	if err != nil {
		writeDoctorError(w, err)
		return
	}
	writeDoctorJSON(w, response)
}

func (a *LocalAPI) handleDoctorRepair(w http.ResponseWriter, r *http.Request) {
	var input doctorRepairRequest
	if err := decodeStrictJSON(r.Body, 4<<10, &input); err != nil {
		writeDoctorError(w, ErrDoctorInvalidRequest)
		return
	}
	if !input.Confirm || input.DisclosureVersion != doctorDisclosureVersion {
		writeDoctorError(w, ErrDoctorDisclosureRequired)
		return
	}
	if !validDoctorRepairAction(input.Action) {
		writeDoctorError(w, ErrDoctorInvalidRequest)
		return
	}
	if !supportedDoctorRepair(input.Action) {
		writeDoctorError(w, ErrDoctorRepairUnsupported)
		return
	}
	if a.d == nil {
		writeDoctorError(w, ErrDoctorInvalidRequest)
		return
	}
	report, err := a.d.networkDoctor().Repair(
		r.Context(), input.PlanID, input.Action, input.Confirm, input.DisclosureVersion,
	)
	if err != nil {
		writeDoctorError(w, err)
		return
	}
	writeDoctorJSON(w, report)
}

func (n *NetworkDoctor) Run(ctx context.Context, confirmed bool, disclosure string) (NetworkDoctorResult, error) {
	if ctx == nil || n == nil || n.d == nil {
		return NetworkDoctorResult{}, ErrDoctorInvalidRequest
	}
	if !confirmed || disclosure != doctorDisclosureVersion {
		return NetworkDoctorResult{}, ErrDoctorDisclosureRequired
	}
	if !n.acquire() {
		return NetworkDoctorResult{}, ErrDoctorBusy
	}
	defer n.release()
	// Starting a newer diagnosis invalidates every prior authorization before
	// any active probe runs. A failed/canceled run must never leave an older
	// plan executable.
	n.clearPlan()

	snapshot, observationErrors := n.captureSnapshot(ctx)
	report, plan := n.newDoctor(snapshot).Diagnose(ctx, snapshot)
	var available []diagnose.RepairActionID
	for _, repair := range plan.Repairs {
		if repair.Applicable && n.canExecuteRepair(repair.Action) {
			available = append(available, repair.Action)
		}
	}
	result := NetworkDoctorResult{
		Schema: doctorAPISchema,
		Report: report, Plan: plan, AvailableRepairs: available,
		ObservationErrors: doctorObservationErrorsForWire(observationErrors),
	}
	if len(available) > 0 {
		token, expiresAt, err := n.issuePlan(available)
		if err != nil {
			return NetworkDoctorResult{}, ErrDoctorUnavailable
		}
		result.PlanID = token
		result.PlanExpiresAt = expiresAt.UTC().Format(time.RFC3339)
	} else {
		n.clearPlan()
	}
	return result, nil
}

func doctorObservationErrorsForWire(in []doctorplatform.ObservationError) []NetworkDoctorObservationError {
	if len(in) == 0 {
		return nil
	}
	out := make([]NetworkDoctorObservationError, 0, len(in))
	for _, item := range in {
		out = append(out, NetworkDoctorObservationError{
			Observation: string(item.Observation),
			Kind:        string(item.Kind),
		})
	}
	return out
}

func (n *NetworkDoctor) newDoctor(snapshot diagnose.Snapshot) *diagnose.Doctor {
	cfg := diagnose.DefaultConfig()
	if snapshot.WireGuard.LinkMTU >= cfg.MTU.SearchLow && snapshot.WireGuard.LinkMTU < cfg.MTU.SearchHigh {
		cfg.MTU.SearchHigh = snapshot.WireGuard.LinkMTU
	}
	deps := diagnose.NewStdNetDeps()
	deps.MTU = doctorplatform.NewPathMTUProber()
	return diagnose.New(cfg, deps)
}

func (n *NetworkDoctor) captureSnapshot(ctx context.Context) (diagnose.Snapshot, []doctorplatform.ObservationError) {
	snapshot := n.d.doctorBaseSnapshot()
	return doctorplatform.New().Capture(ctx, doctorplatform.Inputs{Snapshot: snapshot})
}

func (n *NetworkDoctor) issuePlan(actions []diagnose.RepairActionID) (string, time.Time, error) {
	raw := make([]byte, doctorTokenBytes)
	if n.random == nil {
		return "", time.Time{}, ErrDoctorInvalidRequest
	}
	if _, err := io.ReadFull(n.random, raw); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256(raw)
	for i := range raw {
		raw[i] = 0
	}
	now := time.Now()
	if n.now != nil {
		now = n.now()
	}
	expiresAt := now.Add(doctorPlanTTL)
	allowed := make(map[diagnose.RepairActionID]struct{}, len(actions))
	for _, action := range actions {
		if supportedDoctorRepair(action) {
			allowed[action] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return "", time.Time{}, ErrDoctorRepairNotApplicable
	}
	var runCtx context.Context
	if n.d != nil {
		n.d.mu.Lock()
		runCtx = n.d.runCtx
		n.d.mu.Unlock()
	}
	n.mu.Lock()
	n.plan = doctorPlanAuthorization{
		digest: digest, actions: allowed, expiresAt: expiresAt, runCtx: runCtx,
	}
	n.mu.Unlock()
	return token, expiresAt, nil
}

func (n *NetworkDoctor) clearPlan() {
	n.mu.Lock()
	n.plan = doctorPlanAuthorization{}
	n.mu.Unlock()
}

func parseDoctorPlanID(token string) ([sha256.Size]byte, bool) {
	if len(token) == 0 || len(token) > 128 {
		return [sha256.Size]byte{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != doctorTokenBytes ||
		base64.RawURLEncoding.EncodeToString(raw) != token {
		return [sha256.Size]byte{}, false
	}
	digest := sha256.Sum256(raw)
	for i := range raw {
		raw[i] = 0
	}
	return digest, true
}

func (n *NetworkDoctor) consumePlan(token string, action diagnose.RepairActionID) error {
	if token == "" {
		return ErrDoctorPlanRequired
	}
	digest, ok := parseDoctorPlanID(token)
	if !ok {
		return ErrDoctorPlanMismatch
	}
	now := time.Now()
	if n.now != nil {
		now = n.now()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	plan := n.plan
	if plan.actions == nil {
		return ErrDoctorPlanRequired
	}
	if !now.Before(plan.expiresAt) {
		n.plan = doctorPlanAuthorization{}
		return ErrDoctorPlanExpired
	}
	if plan.runCtx != nil && plan.runCtx.Err() != nil {
		n.plan = doctorPlanAuthorization{}
		return ErrDoctorPlanExpired
	}
	if subtle.ConstantTimeCompare(digest[:], plan.digest[:]) != 1 {
		return ErrDoctorPlanMismatch
	}
	if _, ok := plan.actions[action]; !ok {
		return ErrDoctorPlanMismatch
	}
	n.plan = doctorPlanAuthorization{}
	return nil
}

func (n *NetworkDoctor) Repair(
	ctx context.Context,
	planID string,
	action diagnose.RepairActionID,
	confirmed bool,
	disclosure string,
) (NetworkDoctorExecution, error) {
	if ctx == nil || n == nil || n.d == nil {
		return NetworkDoctorExecution{}, ErrDoctorInvalidRequest
	}
	if !confirmed || disclosure != doctorDisclosureVersion {
		return NetworkDoctorExecution{}, ErrDoctorDisclosureRequired
	}
	if !validDoctorRepairAction(action) {
		return NetworkDoctorExecution{}, ErrDoctorInvalidRequest
	}
	if !supportedDoctorRepair(action) {
		return NetworkDoctorExecution{}, ErrDoctorRepairUnsupported
	}
	if !n.canExecuteRepair(action) {
		return NetworkDoctorExecution{}, ErrDoctorRepairUnsupported
	}
	if !n.acquire() {
		return NetworkDoctorExecution{}, ErrDoctorBusy
	}
	defer n.release()
	if err := n.consumePlan(planID, action); err != nil {
		return NetworkDoctorExecution{}, err
	}

	// Recreate the plan and execution snapshot after consuming the one-use
	// authorization. The opaque plan ID authorizes only the selected action; it
	// never turns stale plan JSON from the client into trusted executable input.
	plannedSnapshot, _ := n.captureSnapshot(ctx)
	_, plan := n.newDoctor(plannedSnapshot).Diagnose(ctx, plannedSnapshot)
	var selected *diagnose.PlannedRepair
	for i := range plan.Repairs {
		if plan.Repairs[i].Action == action {
			selected = &plan.Repairs[i]
			break
		}
	}
	if selected == nil || !selected.Applicable {
		return NetworkDoctorExecution{}, ErrDoctorRepairNotApplicable
	}
	plan.Repairs = []diagnose.PlannedRepair{*selected}
	fresh, _ := n.captureSnapshot(ctx)
	report := n.newDoctor(fresh).ExecutePlan(ctx, fresh, plan, &daemonDoctorExecutor{d: n.d})
	return NetworkDoctorExecution{Schema: doctorExecutionSchema, Execution: report}, nil
}

func marshalDoctorJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", ErrDoctorUnavailable
	}
	if len(data) == 0 || len(data) > maxDoctorJSONBytes {
		return "", ErrDoctorResponseTooLarge
	}
	return string(data), nil
}

func (n *NetworkDoctor) RunJSON(ctx context.Context, confirmed bool, disclosure string) (string, error) {
	result, err := n.Run(ctx, confirmed, disclosure)
	if err != nil {
		return "", err
	}
	return marshalDoctorJSON(result)
}

func (n *NetworkDoctor) RepairJSON(
	ctx context.Context,
	planID string,
	action diagnose.RepairActionID,
	confirmed bool,
	disclosure string,
) (string, error) {
	result, err := n.Repair(ctx, planID, action, confirmed, disclosure)
	if err != nil {
		return "", err
	}
	return marshalDoctorJSON(result)
}

func writeDoctorJSON(w http.ResponseWriter, value any) {
	data, err := marshalDoctorJSON(value)
	if err != nil {
		writeDoctorError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, data)
}

func writeDoctorError(w http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	code := ErrDoctorUnavailable.Error()
	switch {
	case errors.Is(err, ErrDoctorDisclosureRequired):
		status, code = http.StatusPreconditionRequired, ErrDoctorDisclosureRequired.Error()
	case errors.Is(err, ErrDoctorBusy):
		status, code = http.StatusTooManyRequests, ErrDoctorBusy.Error()
	case errors.Is(err, ErrDoctorRepairUnsupported):
		status, code = http.StatusNotImplemented, ErrDoctorRepairUnsupported.Error()
	case errors.Is(err, ErrDoctorPlanRequired):
		status, code = http.StatusPreconditionFailed, ErrDoctorPlanRequired.Error()
	case errors.Is(err, ErrDoctorPlanMismatch):
		status, code = http.StatusPreconditionFailed, ErrDoctorPlanMismatch.Error()
	case errors.Is(err, ErrDoctorPlanExpired):
		status, code = http.StatusGone, ErrDoctorPlanExpired.Error()
	case errors.Is(err, ErrDoctorRepairNotApplicable):
		status, code = http.StatusConflict, ErrDoctorRepairNotApplicable.Error()
	case errors.Is(err, ErrDoctorInvalidRequest):
		status, code = http.StatusBadRequest, ErrDoctorInvalidRequest.Error()
	case errors.Is(err, ErrDoctorResponseTooLarge):
		status, code = http.StatusInternalServerError, ErrDoctorResponseTooLarge.Error()
	case errors.Is(err, ErrDoctorUnavailable):
		status, code = http.StatusServiceUnavailable, ErrDoctorUnavailable.Error()
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, code, status)
}

func (d *Daemon) doctorBaseSnapshot() diagnose.Snapshot {
	d.mu.Lock()
	nm := d.lastNetmap
	nm.Peers = append([]types.Node(nil), nm.Peers...)
	nm.Relays = append([]string(nil), nm.Relays...)
	preferred := d.preferredExit
	exitRouted := d.exitRouted
	state := d.state
	coordURL := d.cfg.CoordURL
	authKey := d.cfg.AuthKey
	relaySpecs := append([]string(nil), d.relaySpecs...)
	if len(relaySpecs) == 0 {
		relaySpecs = append(relaySpecs, nm.Relays...)
	}
	d.mu.Unlock()

	snapshot := diagnose.Snapshot{
		Coordinator: endpointFromURL("coordinator", coordURL, "/v1/healthz"),
		ExitActive:  preferred != "" && exitRouted,
		Secrets:     []string{authKey},
	}
	for _, spec := range relaySpecs {
		if endpoint, ok := endpointFromSpec("relay", spec); ok {
			snapshot.Relays = append(snapshot.Relays, endpoint)
		}
	}
	// The standard HTTP/QUIC adapters cannot yet bind a probe socket to the
	// tunnel interface. While EXIT is active, a more-specific physical host
	// route or DNS rotation could therefore make a successful media request go
	// DIRECT. Report the evidence as unavailable instead of manufacturing
	// EXIT/video health. DIRECT mode remains safe to probe normally.
	if !snapshot.ExitActive {
		snapshot.MediaTargets = defaultDoctorMediaTargets()
	}
	if namer, ok := d.engine.(wgengine.InterfaceNamer); ok {
		snapshot.WireGuard.Interface = namer.InterfaceName()
	}
	snapshot.WireGuard.Up = snapshot.WireGuard.Interface != "" && state == StateRunning

	stats := map[types.Key]wgengine.PeerStat{}
	if reporter, ok := d.engine.(wgengine.PeerStatsReporter); ok {
		if observed, err := reporter.PeerStats(); err == nil {
			stats = observed
		}
	}
	for _, peer := range nm.Peers {
		stat := stats[peer.Key]
		isExit := peer.Role == types.RoleExit && peerMatches(peer, preferred)
		snapshot.WireGuard.Peers = append(snapshot.WireGuard.Peers, diagnose.PeerStatus{
			PublicKey: peer.Key.String(), LastHandshake: stat.LatestHandshake, IsExit: isExit,
			RxBytes: stat.RxBytes, TxBytes: stat.TxBytes,
		})
		if isExit {
			exit := &diagnose.ExitState{
				PeerPublicKey: peer.Key.String(),
				LastHandshake: stat.LatestHandshake,
				RoutePresent:  exitRouted,
			}
			if len(snapshot.MediaTargets) > 0 {
				exit.EgressCanary = &snapshot.MediaTargets[0]
			}
			snapshot.Exit = exit
		}
	}
	return snapshot
}

func endpointFromURL(label, raw, healthPath string) diagnose.Endpoint {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return diagnose.Endpoint{Label: label}
	}
	port := 443
	if parsed.Scheme == "http" {
		port = 80
	}
	if explicit := parsed.Port(); explicit != "" {
		if value, parseErr := strconv.Atoi(explicit); parseErr == nil {
			port = value
		}
	}
	return diagnose.Endpoint{
		Label: label, Host: parsed.Hostname(), Port: port,
		Scheme: parsed.Scheme, HealthPath: healthPath,
	}
}

func endpointFromSpec(label, spec string) (diagnose.Endpoint, bool) {
	raw := strings.TrimSpace(spec)
	if raw == "" {
		return diagnose.Endpoint{}, false
	}
	if strings.Contains(raw, "|") {
		raw, _, _ = parseRelaySpec(raw)
	}
	if strings.Contains(raw, "://") {
		endpoint := endpointFromURL(label, raw, "")
		return endpoint, endpoint.Host != "" && endpoint.Port > 0
	}
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		return diagnose.Endpoint{}, false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return diagnose.Endpoint{}, false
	}
	return diagnose.Endpoint{Label: label, Host: host, Port: port}, true
}

func decodeStrictJSON(body io.Reader, limit int64, dst any) error {
	if body == nil || limit <= 0 {
		return errors.New("missing body")
	}
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return errors.New("invalid body")
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

func supportedDoctorRepair(action diagnose.RepairActionID) bool {
	switch action {
	case diagnose.ActionFlushDNS:
		return true
	default:
		// Rebuilding an EXIT is deliberately not in the production-safe
		// allowlist. ClearExit resumes physical egress before SetExit can
		// reinstall the protected route, so the two-step operation has a
		// transient DIRECT leak window and cannot be rolled back after traffic
		// escapes. It also cannot prove that sustained EXIT egress recovered.
		// Keep diagnosis and the proposed action in the report, but reject
		// execution until the data plane provides one atomic, fail-closed
		// rebuild primitive with an egress postcondition.
		return false
	}
}

func validDoctorRepairAction(action diagnose.RepairActionID) bool {
	if len(action) == 0 || len(action) > 64 {
		return false
	}
	for i := 0; i < len(action); i++ {
		c := action[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func (n *NetworkDoctor) canExecuteRepair(action diagnose.RepairActionID) bool {
	if n == nil || n.d == nil || !supportedDoctorRepair(action) {
		return false
	}
	switch action {
	case diagnose.ActionFlushDNS:
		n.d.mu.Lock()
		available := n.d.systemResolver != nil
		runCtx := n.d.runCtx
		n.d.mu.Unlock()
		return available && (runCtx == nil || runCtx.Err() == nil)
	default:
		return false
	}
}

type daemonDoctorExecutor struct {
	d            *Daemon
	capturedExit string
}

func (e *daemonDoctorExecutor) CaptureSnapshot(_ context.Context, req diagnose.SnapshotRequest) (diagnose.SnapshotData, error) {
	if req.Kind != "exit-selection" {
		return diagnose.SnapshotData{}, fmt.Errorf("unsupported snapshot kind %q", req.Kind)
	}
	e.d.mu.Lock()
	exit := e.d.preferredExit
	e.d.mu.Unlock()
	if exit == "" {
		return diagnose.SnapshotData{}, errors.New("no selected exit")
	}
	e.capturedExit = exit
	return diagnose.SnapshotData{Kind: req.Kind, Values: map[string]string{"exit": exit}}, nil
}

func (e *daemonDoctorExecutor) Apply(ctx context.Context, step diagnose.Step, snapshots []diagnose.SnapshotData) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch step.Op {
	case diagnose.OpFlushDNS:
		e.d.mu.Lock()
		resolver := e.d.systemResolver
		runCtx := e.d.runCtx
		e.d.mu.Unlock()
		if resolver == nil || (runCtx != nil && runCtx.Err() != nil) {
			return errors.New("DNS cache flush unavailable")
		}
		if err := resolver.FlushCache(); err != nil {
			return errors.New("DNS cache flush failed")
		}
		return nil
	case diagnose.OpClearExit:
		if err := e.d.ClearExit(); err != nil {
			return errors.New("exit clear failed")
		}
		return nil
	case diagnose.OpSetExit:
		exit := snapshotValue(snapshots, "exit-selection", "exit")
		if exit == "" {
			exit = e.capturedExit
		}
		if exit == "" {
			return errors.New("captured exit is unavailable")
		}
		if err := e.d.SetExit(exit); err != nil {
			return errors.New("exit selection failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported repair operation %q", step.Op)
	}
}

func (e *daemonDoctorExecutor) CheckPostcondition(ctx context.Context, id diagnose.PostconditionID, _ []diagnose.SnapshotData) (bool, error) {
	switch id {
	case diagnose.PostDNSResolves:
		target := defaultDoctorMediaTargets()[0]
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", target.Host)
		if err != nil {
			return false, err
		}
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{},
			Config: &tls.Config{
				MinVersion: tls.VersionTLS13,
				ServerName: target.Host,
			},
		}
		return doctorDNSAddressesAuthenticate(ctx, addrs, doctorUsableAddressFamilies(), target.Port, func(ctx context.Context, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", address)
		})
	case diagnose.PostKillSwitchArmed:
		return e.d.guard.Current().Enabled, nil
	case diagnose.PostExitRoutePresent:
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			e.d.mu.Lock()
			ok := e.d.exitRouted && e.d.preferredExit != ""
			e.d.mu.Unlock()
			if ok {
				return true, nil
			}
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-ticker.C:
			}
		}
	default:
		return false, fmt.Errorf("unsupported postcondition %q", id)
	}
}

var doctorMeshPrefix = netip.MustParsePrefix("100.64.0.0/10")

func doctorDNSAnswersSafe(addrs []netip.Addr) bool {
	if len(addrs) == 0 {
		return false
	}
	for _, raw := range addrs {
		addr := raw.Unmap()
		if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() ||
			addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
			addr.IsLinkLocalMulticast() || addr.IsMulticast() ||
			doctorMeshPrefix.Contains(addr) {
			return false
		}
	}
	return true
}

// doctorDNSAddressesAuthenticate binds the address-class check and TLS
// identity proof to one immutable resolver result. Dialing exact IP literals
// prevents a second DNS lookup from swapping the evidence between validation
// and use. Every returned address in a locally usable family must authenticate
// the expected SNI; all addresses are still classified before family
// filtering. This avoids penalizing a genuine single-stack host merely because
// the target also publishes the other family.
func doctorDNSAddressesAuthenticate(
	ctx context.Context,
	addrs []netip.Addr,
	families doctorAddressFamilies,
	port int,
	dial func(context.Context, string) (net.Conn, error),
) (bool, error) {
	if ctx == nil || port < 1 || port > 65535 || dial == nil || !doctorDNSAnswersSafe(addrs) {
		return false, nil
	}
	authenticated := 0
	for _, raw := range addrs {
		addr := raw.Unmap()
		if (addr.Is4() && !families.IPv4) || (addr.Is6() && !families.IPv6) {
			continue
		}
		address := net.JoinHostPort(addr.String(), strconv.Itoa(port))
		conn, err := dial(ctx, address)
		if err != nil {
			return false, err
		}
		if err := conn.Close(); err != nil {
			return false, err
		}
		authenticated++
	}
	return authenticated > 0, nil
}

type doctorAddressFamilies struct {
	IPv4 bool
	IPv6 bool
}

func doctorUsableAddressFamilies() doctorAddressFamilies {
	var families doctorAddressFamilies
	interfaces, err := net.Interfaces()
	if err != nil {
		return families
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, raw := range addrs {
			prefix, err := netip.ParsePrefix(raw.String())
			if err != nil {
				continue
			}
			addr := prefix.Addr().Unmap()
			if !addr.IsValid() || !addr.IsGlobalUnicast() ||
				addr.IsLoopback() || addr.IsLinkLocalUnicast() {
				continue
			}
			if addr.Is4() {
				families.IPv4 = true
			} else {
				families.IPv6 = true
			}
		}
	}
	return families
}

func snapshotValue(snapshots []diagnose.SnapshotData, kind, key string) string {
	for _, snapshot := range snapshots {
		if snapshot.Kind == kind {
			return snapshot.Values[key]
		}
	}
	return ""
}

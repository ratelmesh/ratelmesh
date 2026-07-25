package daemon

import (
	"context"
	"crypto/tls"
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
	"time"

	"github.com/shan25519/ratelmesh/internal/diagnose"
	"github.com/shan25519/ratelmesh/internal/doctorplatform"
	"github.com/shan25519/ratelmesh/internal/types"
	"github.com/shan25519/ratelmesh/internal/wgengine"
)

type doctorResponse struct {
	Report            diagnose.Report                   `json:"report"`
	Plan              diagnose.RepairPlan               `json:"plan"`
	AvailableRepairs  []diagnose.RepairActionID         `json:"availableRepairs,omitempty"`
	ObservationErrors []doctorplatform.ObservationError `json:"observationErrors,omitempty"`
}

const doctorDisclosureVersion = "v1"

type doctorRunRequest struct {
	Confirm           bool   `json:"confirm"`
	DisclosureVersion string `json:"disclosureVersion"`
}

type doctorRepairRequest struct {
	Action            diagnose.RepairActionID `json:"action"`
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
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !input.Confirm || input.DisclosureVersion != doctorDisclosureVersion {
		http.Error(w, "current diagnostic disclosure confirmation required", http.StatusPreconditionRequired)
		return
	}
	if !a.acquireDoctorRun() {
		http.Error(w, "diagnosis already running", http.StatusTooManyRequests)
		return
	}
	defer a.releaseDoctorRun()
	response := a.runDoctor(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(response)
}

func (a *LocalAPI) handleDoctorRepair(w http.ResponseWriter, r *http.Request) {
	var input doctorRepairRequest
	if err := decodeStrictJSON(r.Body, 4<<10, &input); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !input.Confirm || input.DisclosureVersion != doctorDisclosureVersion {
		http.Error(w, "current diagnostic disclosure confirmation required", http.StatusPreconditionRequired)
		return
	}
	if !supportedDoctorRepair(input.Action) {
		http.Error(w, "repair is not safely available on this build", http.StatusNotImplemented)
		return
	}
	if !a.acquireDoctorRun() {
		http.Error(w, "diagnosis or repair already running", http.StatusTooManyRequests)
		return
	}
	defer a.releaseDoctorRun()

	// Repairs are serialized because they touch shared routing/firewall state.
	// The plan and execution snapshot are both recaptured after the lock.
	a.doctorRepairMu.Lock()
	defer a.doctorRepairMu.Unlock()

	planned := a.runDoctor(r.Context())
	var selected *diagnose.PlannedRepair
	for i := range planned.Plan.Repairs {
		if planned.Plan.Repairs[i].Action == input.Action {
			selected = &planned.Plan.Repairs[i]
			break
		}
	}
	if selected == nil || !selected.Applicable {
		http.Error(w, "repair is not currently applicable", http.StatusConflict)
		return
	}
	planned.Plan.Repairs = []diagnose.PlannedRepair{*selected}

	fresh, _ := a.captureDoctorSnapshot(r.Context())
	exec := &daemonDoctorExecutor{d: a.d}
	report := a.newDoctor(fresh).ExecutePlan(r.Context(), fresh, planned.Plan, exec)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(report)
}

func (a *LocalAPI) acquireDoctorRun() bool {
	a.doctorRunOnce.Do(func() { a.doctorRun = make(chan struct{}, 1) })
	select {
	case a.doctorRun <- struct{}{}:
		return true
	default:
		return false
	}
}

func (a *LocalAPI) releaseDoctorRun() {
	<-a.doctorRun
}

func (a *LocalAPI) runDoctor(ctx context.Context) doctorResponse {
	snapshot, observationErrors := a.captureDoctorSnapshot(ctx)
	report, plan := a.newDoctor(snapshot).Diagnose(ctx, snapshot)
	var available []diagnose.RepairActionID
	for _, repair := range plan.Repairs {
		if repair.Applicable && supportedDoctorRepair(repair.Action) {
			available = append(available, repair.Action)
		}
	}
	return doctorResponse{
		Report: report, Plan: plan, AvailableRepairs: available,
		ObservationErrors: observationErrors,
	}
}

func (a *LocalAPI) newDoctor(snapshot diagnose.Snapshot) *diagnose.Doctor {
	cfg := diagnose.DefaultConfig()
	if snapshot.WireGuard.LinkMTU >= cfg.MTU.SearchLow && snapshot.WireGuard.LinkMTU < cfg.MTU.SearchHigh {
		cfg.MTU.SearchHigh = snapshot.WireGuard.LinkMTU
	}
	deps := diagnose.NewStdNetDeps()
	deps.MTU = doctorplatform.NewPathMTUProber()
	return diagnose.New(cfg, deps)
}

func (a *LocalAPI) captureDoctorSnapshot(ctx context.Context) (diagnose.Snapshot, []doctorplatform.ObservationError) {
	snapshot := a.d.doctorBaseSnapshot()
	return doctorplatform.New().Capture(ctx, doctorplatform.Inputs{Snapshot: snapshot})
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
		if err := e.d.systemResolver.FlushCache(); err != nil {
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

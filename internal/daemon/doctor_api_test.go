package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/diagnose"
	"github.com/ratelmesh/ratelmesh/internal/types"
	"github.com/ratelmesh/ratelmesh/internal/wgengine"
)

func TestDoctorRepairRequestRejectsUnknownFieldsAndRequiresConfirmation(t *testing.T) {
	api := &LocalAPI{}
	tests := []struct {
		body string
		want int
	}{
		{body: `{"action":"flush-dns","confirm":true,"command":"rm"}`, want: http.StatusBadRequest},
		{body: `{"action":"flush-dns","confirm":false}`, want: http.StatusPreconditionRequired},
		{body: `{"action":"flush-dns","confirm":true}`, want: http.StatusPreconditionRequired},
		{body: `{"action":"flush-dns","confirm":true,"disclosureVersion":"old"}`, want: http.StatusPreconditionRequired},
		{body: `{"action":"","confirm":true,"disclosureVersion":"v1"}`, want: http.StatusBadRequest},
		{body: `{"action":"rebuild-exit","confirm":true,"disclosureVersion":"v1"}`, want: http.StatusNotImplemented},
		{body: `{"action":"restart-wireguard","confirm":true,"disclosureVersion":"v1"}`, want: http.StatusNotImplemented},
	}
	for _, test := range tests {
		req := httptest.NewRequest(http.MethodPost, "/localapi/doctor/repair", strings.NewReader(test.body))
		rec := httptest.NewRecorder()
		api.handleDoctorRepair(rec, req)
		if rec.Code != test.want {
			t.Fatalf("body %q: status=%d want=%d response=%q", test.body, rec.Code, test.want, rec.Body.String())
		}
	}
}

func TestDoctorRepairAllowlistIsClosed(t *testing.T) {
	for _, action := range []diagnose.RepairActionID{
		diagnose.ActionFlushDNS,
	} {
		if !supportedDoctorRepair(action) {
			t.Fatalf("expected %q to be supported", action)
		}
	}
	for _, action := range []diagnose.RepairActionID{
		"", "run-command", diagnose.ActionRebuildExit, diagnose.ActionLowerMTU, diagnose.ActionRestartWireGuard,
		diagnose.ActionRearmKillSwitch,
	} {
		if supportedDoctorRepair(action) {
			t.Fatalf("unexpected action %q supported", action)
		}
	}
}

func TestDoctorEndpointParsingIsStrict(t *testing.T) {
	got := endpointFromURL("coordinator", "https://coord.example:8443/base", "/v1/healthz")
	if got.Host != "coord.example" || got.Port != 8443 || got.Scheme != "https" {
		t.Fatalf("unexpected endpoint: %+v", got)
	}
	if _, ok := endpointFromSpec("relay", "relay.example:not-a-port"); ok {
		t.Fatal("invalid relay port accepted")
	}
	if _, ok := endpointFromSpec("relay", "relay.example"); ok {
		t.Fatal("relay without port accepted")
	}
}

func TestDoctorDefaultMediaCanaryStaysInsideProductPrivacyBoundary(t *testing.T) {
	targets := defaultDoctorMediaTargets()
	if len(targets) != 1 {
		t.Fatalf("default media targets = %d, want 1", len(targets))
	}
	target := targets[0]
	if target.Label != "ratelmesh-media-canary" ||
		target.Host != "ratelmesh.com" ||
		target.Port != 443 ||
		target.Scheme != "https" ||
		target.HealthPath != "/og.png" ||
		target.EvidenceSource != "ratelmesh-web-cdn" {
		t.Fatalf("unexpected default media target: %+v", target)
	}
	for _, forbidden := range []string{"googleapis.com", "youtube.com", "googlevideo.com"} {
		if strings.Contains(target.Host, forbidden) {
			t.Fatalf("third-party media target restored: %q", target.Host)
		}
	}
}

func TestDoctorDNSPostconditionRejectsEveryUnsafeAnswer(t *testing.T) {
	public4 := netip.MustParseAddr("8.8.8.8")
	public6 := netip.MustParseAddr("2606:4700:4700::1111")
	if !doctorDNSAnswersSafe([]netip.Addr{public4, public6}) {
		t.Fatal("public DNS answers rejected")
	}
	for _, unsafe := range []string{
		"127.0.0.1",
		"10.0.0.1",
		"100.64.0.5",
		"169.254.1.1",
		"::1",
		"fc00::1",
		"fe80::1",
		"224.0.0.1",
		"ff02::1",
	} {
		addrs := []netip.Addr{public4, netip.MustParseAddr(unsafe)}
		if doctorDNSAnswersSafe(addrs) {
			t.Fatalf("mixed answer containing %s reported safe", unsafe)
		}
	}
	if doctorDNSAnswersSafe(nil) {
		t.Fatal("empty DNS answer reported safe")
	}
}

func TestDoctorDNSIdentityProofPinsEveryResolvedAddress(t *testing.T) {
	addrs := []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}
	var dialed []string
	ok, err := doctorDNSAddressesAuthenticate(context.Background(), addrs, doctorAddressFamilies{IPv4: true, IPv6: true}, 443,
		func(_ context.Context, address string) (net.Conn, error) {
			dialed = append(dialed, address)
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		})
	if err != nil || !ok {
		t.Fatalf("identity proof = %v, %v", ok, err)
	}
	want := []string{"8.8.8.8:443", "[2606:4700:4700::1111]:443"}
	if strings.Join(dialed, ",") != strings.Join(want, ",") {
		t.Fatalf("dialed = %v, want %v", dialed, want)
	}
}

func TestDoctorDNSIdentityProofFailsOnAnyAddress(t *testing.T) {
	addrs := []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("1.1.1.1"),
	}
	calls := 0
	ok, err := doctorDNSAddressesAuthenticate(context.Background(), addrs, doctorAddressFamilies{IPv4: true, IPv6: true}, 443,
		func(_ context.Context, _ string) (net.Conn, error) {
			calls++
			if calls == 2 {
				return nil, errors.New("TLS identity mismatch")
			}
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		})
	if err == nil || ok {
		t.Fatalf("mixed identity proof = %v, %v", ok, err)
	}
}

func TestDoctorDNSIdentityProofUsesOnlyLocallyUsableFamilies(t *testing.T) {
	addrs := []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}
	var dialed []string
	ok, err := doctorDNSAddressesAuthenticate(
		context.Background(),
		addrs,
		doctorAddressFamilies{IPv4: true},
		443,
		func(_ context.Context, address string) (net.Conn, error) {
			dialed = append(dialed, address)
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		},
	)
	if err != nil || !ok {
		t.Fatalf("IPv4-only identity proof = %v, %v", ok, err)
	}
	if len(dialed) != 1 || dialed[0] != "8.8.8.8:443" {
		t.Fatalf("IPv4-only dialed = %v", dialed)
	}
	if ok, err := doctorDNSAddressesAuthenticate(
		context.Background(), addrs, doctorAddressFamilies{}, 443,
		func(context.Context, string) (net.Conn, error) {
			t.Fatal("dial called without a usable family")
			return nil, nil
		},
	); err != nil || ok {
		t.Fatalf("no-family identity proof = %v, %v", ok, err)
	}
}

func TestDoctorSnapshotDisablesUnboundMediaEvidenceWhileExitIsActive(t *testing.T) {
	private, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	peer := types.Node{
		Key: private.Public(), Name: "exit", Role: types.RoleExit,
		MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
	}
	d := &Daemon{
		cfg:           Config{CoordURL: "https://control.ratelmesh.com"},
		engine:        wgengine.NewStub(nil),
		lastNetmap:    types.Netmap{Peers: []types.Node{peer}},
		preferredExit: peer.Name,
		exitRouted:    true,
		state:         StateRunning,
	}
	snapshot := d.doctorBaseSnapshot()
	if !snapshot.ExitActive || snapshot.Exit == nil {
		t.Fatalf("expected active EXIT snapshot: %+v", snapshot)
	}
	if len(snapshot.MediaTargets) != 0 || snapshot.Exit.EgressCanary != nil {
		t.Fatalf("unbound EXIT canary evidence enabled: %+v", snapshot)
	}
}

func TestDoctorActiveEndpointIsPostOnly(t *testing.T) {
	api := &LocalAPI{}
	req := httptest.NewRequest(http.MethodGet, "/localapi/doctor", nil)
	rec := httptest.NewRecorder()
	api.buildMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET status=%d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestDoctorActiveEndpointRequiresCurrentDisclosure(t *testing.T) {
	api := &LocalAPI{}
	tests := []struct {
		body string
		want int
	}{
		{body: ``, want: http.StatusBadRequest},
		{body: `{}`, want: http.StatusPreconditionRequired},
		{body: `{"confirm":false,"disclosureVersion":"v1"}`, want: http.StatusPreconditionRequired},
		{body: `{"confirm":true,"disclosureVersion":"old"}`, want: http.StatusPreconditionRequired},
		{body: `{"confirm":true,"disclosureVersion":"v1","extra":true}`, want: http.StatusBadRequest},
	}
	for _, test := range tests {
		req := httptest.NewRequest(http.MethodPost, "/localapi/doctor", strings.NewReader(test.body))
		rec := httptest.NewRecorder()
		api.handleDoctor(rec, req)
		if rec.Code != test.want {
			t.Fatalf("body %q: status=%d want=%d response=%q", test.body, rec.Code, test.want, rec.Body.String())
		}
	}
}

func TestDoctorRunAdmissionIsSingleFlight(t *testing.T) {
	doctor := newNetworkDoctor(&Daemon{})
	if !doctor.acquire() {
		t.Fatal("first diagnosis was not admitted")
	}
	if doctor.acquire() {
		t.Fatal("concurrent diagnosis was admitted")
	}
	doctor.release()
	if !doctor.acquire() {
		t.Fatal("diagnosis was not admitted after release")
	}
	doctor.release()
}

func TestDoctorPlanAuthorizationIsOpaqueOneUseAndExpiring(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	doctor := newNetworkDoctor(&Daemon{})
	doctor.now = func() time.Time { return now }
	doctor.random = bytes.NewReader(bytes.Repeat([]byte{0x5a}, doctorTokenBytes*2))

	planID, expiresAt, err := doctor.issuePlan([]diagnose.RepairActionID{diagnose.ActionFlushDNS})
	if err != nil {
		t.Fatal(err)
	}
	if planID == "" || !expiresAt.Equal(now.Add(doctorPlanTTL)) {
		t.Fatalf("plan authorization = %q, %v", planID, expiresAt)
	}
	wrong := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, doctorTokenBytes))
	if err := doctor.consumePlan(wrong, diagnose.ActionFlushDNS); !errors.Is(err, ErrDoctorPlanMismatch) {
		t.Fatalf("wrong plan ID = %v", err)
	}
	if err := doctor.consumePlan("not-base64!", diagnose.ActionFlushDNS); !errors.Is(err, ErrDoctorPlanMismatch) {
		t.Fatalf("malformed non-empty plan ID = %v", err)
	}
	if err := doctor.consumePlan(planID, diagnose.ActionRebuildExit); !errors.Is(err, ErrDoctorPlanMismatch) {
		t.Fatalf("wrong action = %v", err)
	}
	if err := doctor.consumePlan(planID, diagnose.ActionFlushDNS); err != nil {
		t.Fatalf("valid plan rejected after token/action mismatch: %v", err)
	}
	if err := doctor.consumePlan(planID, diagnose.ActionFlushDNS); !errors.Is(err, ErrDoctorPlanRequired) {
		t.Fatalf("one-use plan replay = %v", err)
	}

	expiring, _, err := doctor.issuePlan([]diagnose.RepairActionID{diagnose.ActionFlushDNS})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(doctorPlanTTL)
	if err := doctor.consumePlan(expiring, diagnose.ActionFlushDNS); !errors.Is(err, ErrDoctorPlanExpired) {
		t.Fatalf("expired plan = %v", err)
	}
}

func TestDoctorPlanExpiresWhenDaemonRunSessionEnds(t *testing.T) {
	runCtx, cancel := context.WithCancel(context.Background())
	d := &Daemon{runCtx: runCtx}
	doctor := newNetworkDoctor(d)
	doctor.random = bytes.NewReader(bytes.Repeat([]byte{0x6b}, doctorTokenBytes))
	planID, _, err := doctor.issuePlan([]diagnose.RepairActionID{diagnose.ActionFlushDNS})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := doctor.consumePlan(planID, diagnose.ActionFlushDNS); !errors.Is(err, ErrDoctorPlanExpired) {
		t.Fatalf("plan survived daemon run cancellation: %v", err)
	}
}

func TestDoctorPlanHasExactlyOneConcurrentConsumer(t *testing.T) {
	doctor := newNetworkDoctor(&Daemon{})
	planID, _, err := doctor.issuePlan([]diagnose.RepairActionID{diagnose.ActionFlushDNS})
	if err != nil {
		t.Fatal(err)
	}
	const consumers = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	var countMu sync.Mutex
	successes := 0
	for i := 0; i < consumers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if doctor.consumePlan(planID, diagnose.ActionFlushDNS) == nil {
				countMu.Lock()
				successes++
				countMu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if successes != 1 {
		t.Fatalf("successful concurrent consumers = %d, want 1", successes)
	}
}

func TestDoctorInvalidOrUnsupportedActionDoesNotConsumePlan(t *testing.T) {
	d := &Daemon{systemResolver: &cacheCountingResolver{}}
	doctor := newNetworkDoctor(d)
	planID, _, err := doctor.issuePlan([]diagnose.RepairActionID{diagnose.ActionFlushDNS})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := doctor.Repair(
		context.Background(), planID, "", true, doctorDisclosureVersion,
	); !errors.Is(err, ErrDoctorInvalidRequest) {
		t.Fatalf("empty action = %v", err)
	}
	if _, err := doctor.Repair(
		context.Background(), planID, "run-command", true, doctorDisclosureVersion,
	); !errors.Is(err, ErrDoctorRepairUnsupported) {
		t.Fatalf("unsupported action = %v", err)
	}
	if err := doctor.consumePlan(planID, diagnose.ActionFlushDNS); err != nil {
		t.Fatalf("valid plan burned by rejected action: %v", err)
	}
}

func TestDoctorNewDiagnosisInvalidatesPriorPlan(t *testing.T) {
	doctor := newNetworkDoctor(&Daemon{})
	oldPlanID, _, err := doctor.issuePlan([]diagnose.RepairActionID{diagnose.ActionFlushDNS})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = doctor.Run(ctx, true, doctorDisclosureVersion)
	if err := doctor.consumePlan(oldPlanID, diagnose.ActionFlushDNS); err == nil {
		t.Fatal("prior plan remained valid after a newer diagnosis")
	}
}

func TestDoctorRepairRequiresPlanAndReturnsStableError(t *testing.T) {
	api := &LocalAPI{d: &Daemon{systemResolver: &cacheCountingResolver{}}}
	req := httptest.NewRequest(http.MethodPost, "/localapi/doctor/repair", strings.NewReader(
		`{"action":"flush-dns","confirm":true,"disclosureVersion":"v1"}`,
	))
	rec := httptest.NewRecorder()
	api.handleDoctorRepair(rec, req)
	if rec.Code != http.StatusPreconditionFailed ||
		strings.TrimSpace(rec.Body.String()) != ErrDoctorPlanRequired.Error() {
		t.Fatalf("missing plan response = %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("error response cache policy = %q", rec.Header().Get("Cache-Control"))
	}
}

func TestDoctorRepairCapabilityRequiresRuntimeBackend(t *testing.T) {
	doctor := newNetworkDoctor(&Daemon{})
	if doctor.canExecuteRepair(diagnose.ActionFlushDNS) {
		t.Fatal("flush-dns repair offered without a system resolver")
	}
	runCtx, cancel := context.WithCancel(context.Background())
	cancel()
	doctor = newNetworkDoctor(&Daemon{
		systemResolver: &cacheCountingResolver{},
		runCtx:         runCtx,
	})
	if doctor.canExecuteRepair(diagnose.ActionFlushDNS) {
		t.Fatal("flush-dns repair offered after the daemon run ended")
	}
}

func TestDoctorRepairCapabilityAndExecutorReadResolverUnderDaemonLock(t *testing.T) {
	resolver := &cacheCountingResolver{}
	d := &Daemon{systemResolver: resolver}
	doctor := newNetworkDoctor(d)
	executor := &daemonDoctorExecutor{d: d}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 10000; i++ {
			d.mu.Lock()
			if i%2 == 0 {
				d.systemResolver = nil
			} else {
				d.systemResolver = resolver
			}
			d.mu.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 10000; i++ {
			_ = doctor.canExecuteRepair(diagnose.ActionFlushDNS)
			_ = executor.Apply(
				context.Background(), diagnose.Step{Op: diagnose.OpFlushDNS}, nil,
			)
		}
	}()
	close(start)
	wg.Wait()
}

func TestDoctorJSONEnvelopeIsBounded(t *testing.T) {
	payload, err := marshalDoctorJSON(NetworkDoctorResult{Schema: doctorAPISchema})
	if err != nil || !strings.Contains(payload, `"schema":"ratelmesh.doctor.api/v1"`) {
		t.Fatalf("stable envelope = %q, %v", payload, err)
	}
	if _, err := marshalDoctorJSON(strings.Repeat("x", maxDoctorJSONBytes+1)); !errors.Is(err, ErrDoctorResponseTooLarge) {
		t.Fatalf("oversized response = %v", err)
	}
	exact, err := marshalDoctorJSON(strings.Repeat("x", maxDoctorJSONBytes-2))
	if err != nil || len(exact) != maxDoctorJSONBytes {
		t.Fatalf("exact-size response = %d bytes, %v", len(exact), err)
	}
	if _, err := marshalDoctorJSON(strings.Repeat("x", maxDoctorJSONBytes-1)); !errors.Is(err, ErrDoctorResponseTooLarge) {
		t.Fatalf("one-byte-oversized response = %v", err)
	}
}

func TestDoctorObservationErrorsUseStableWireFieldNames(t *testing.T) {
	payload, err := marshalDoctorJSON(NetworkDoctorResult{
		Schema: doctorAPISchema,
		ObservationErrors: []NetworkDoctorObservationError{{
			Observation: "dns",
			Kind:        "unavailable",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, `"observation":"dns"`) ||
		!strings.Contains(payload, `"kind":"unavailable"`) ||
		strings.Contains(payload, `"Observation"`) ||
		strings.Contains(payload, `"Kind"`) {
		t.Fatalf("unstable observation error JSON: %s", payload)
	}
}

func TestDoctorUnknownErrorIsNotExposed(t *testing.T) {
	rec := httptest.NewRecorder()
	writeDoctorError(rec, errors.New("secret path /Users/example/private"))
	if rec.Code != http.StatusServiceUnavailable ||
		strings.TrimSpace(rec.Body.String()) != ErrDoctorUnavailable.Error() {
		t.Fatalf("unknown error response = %d %q", rec.Code, rec.Body.String())
	}
}

type doctorFailedPostconditionExecutor struct{}

func (doctorFailedPostconditionExecutor) CaptureSnapshot(
	context.Context, diagnose.SnapshotRequest,
) (diagnose.SnapshotData, error) {
	return diagnose.SnapshotData{}, nil
}

func (doctorFailedPostconditionExecutor) Apply(
	context.Context, diagnose.Step, []diagnose.SnapshotData,
) error {
	return nil
}

func (doctorFailedPostconditionExecutor) CheckPostcondition(
	context.Context, diagnose.PostconditionID, []diagnose.SnapshotData,
) (bool, error) {
	return false, nil
}

func TestDoctorFlushDNSFailureNeverClaimsRollback(t *testing.T) {
	snapshot := diagnose.Snapshot{
		DNS: diagnose.DNSState{Servers: []netip.Addr{netip.MustParseAddr("1.1.1.1")}},
	}
	env := &diagnose.Env{
		Snapshot: snapshot,
		Config:   diagnose.DefaultConfig(),
		Deps:     diagnose.NewStdNetDeps(),
	}
	plan := diagnose.Plan(env, []diagnose.Finding{{Code: diagnose.CodeDNSTimeout}})
	execution := diagnose.Execute(
		context.Background(), env, plan, doctorFailedPostconditionExecutor{},
	)
	payload, err := marshalDoctorJSON(NetworkDoctorExecution{
		Schema: doctorExecutionSchema, Execution: execution,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, `"status":"uncertain"`) ||
		!strings.Contains(payload, `"error":"repair_uncertain"`) ||
		strings.Contains(payload, `"status":"rolled_back"`) {
		t.Fatalf("flush-DNS rollback semantics are misleading: %s", payload)
	}
}

func TestDoctorSnapshotCarriesWireGuardCounters(t *testing.T) {
	private, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerKey := private.Public()
	engine := wgengine.NewStub(nil)
	now := time.Now()
	engine.SetPeerStat(peerKey, wgengine.PeerStat{
		LatestHandshake: now,
		RxBytes:         1234,
		TxBytes:         5678,
	})
	d := &Daemon{
		engine: engine,
		state:  StateRunning,
		lastNetmap: types.Netmap{Peers: []types.Node{{
			Name: "peer", Key: peerKey,
		}}},
	}
	snapshot := d.doctorBaseSnapshot()
	if len(snapshot.WireGuard.Peers) != 1 {
		t.Fatalf("peer snapshots = %d, want 1", len(snapshot.WireGuard.Peers))
	}
	got := snapshot.WireGuard.Peers[0]
	if got.LastHandshake != now || got.RxBytes != 1234 || got.TxBytes != 5678 {
		t.Fatalf("WireGuard evidence lost engine counters: %+v", got)
	}
}

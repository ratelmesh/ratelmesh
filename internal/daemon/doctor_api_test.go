package daemon

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/shan25519/ratelmesh/internal/diagnose"
	"github.com/shan25519/ratelmesh/internal/types"
	"github.com/shan25519/ratelmesh/internal/wgengine"
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
	api := &LocalAPI{}
	if !api.acquireDoctorRun() {
		t.Fatal("first diagnosis was not admitted")
	}
	if api.acquireDoctorRun() {
		t.Fatal("concurrent diagnosis was admitted")
	}
	api.releaseDoctorRun()
	if !api.acquireDoctorRun() {
		t.Fatal("diagnosis was not admitted after release")
	}
	api.releaseDoctorRun()
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

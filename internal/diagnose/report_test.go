package diagnose

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// secretSnapshot embeds identifiers and secrets throughout the snapshot and
// pairs it with failing deps so probes emit findings whose evidence carries the
// hosts and targets. The report must not expose any of the raw values.
func secretSnapshot() (Snapshot, []string) {
	const (
		authKey      = "rm-authkey-SUPERSECRET-abc123def456"
		sessionTok   = "session-token-zzz-99887766"
		coordHost    = "coord-tenant-alice.example.net"
		relayHost    = "relay-tenant-alice.example.net"
		mediaHost    = "video-tenant-alice.example.net"
		peerKey      = "kZ9xQwErTyUiOpAsDfGhJkLzXcVbNmQoPlMkNjBhVgY="
		searchDom    = "alice-corp.internal"
		connTargetV4 = "1.1.1.1" // a config value; redacted by pattern AND now registered per-run
	)
	snap := Snapshot{
		Coordinator: Endpoint{Label: "coordinator", Host: coordHost, Port: 8443},
		Relays:      []Endpoint{{Label: "relay-1", Host: relayHost, Port: 443}},
		Exit:        &ExitState{PeerPublicKey: peerKey, RoutePresent: false},
		WireGuard: WireGuardState{
			Interface: "utun7", Up: true,
			Peers: []PeerStatus{{PublicKey: peerKey}},
		},
		Addresses:    []InterfaceAddr{{Interface: "en0", Family: FamilyV4, Addr: mustAddr("198.51.100.7")}},
		DNS:          DNSState{SearchDomains: []string{searchDom}},
		MediaTargets: []Endpoint{{Label: "video", Host: mediaHost, Port: 443, Scheme: "https"}},
		ExitActive:   true,
		Secrets:      []string{authKey, sessionTok},
	}
	// The raw literals that must never appear in the emitted report.
	raw := []string{authKey, sessionTok, coordHost, relayHost, mediaHost, peerKey, searchDom, connTargetV4}
	return snap, raw
}

func TestReportContainsNoRawSecrets(t *testing.T) {
	snap, raw := secretSnapshot()
	deps := Deps{
		Dialer:   alwaysFailDialer{},
		Resolver: fakeResolver{addrs: addrs("127.0.0.1")}, // triggers a poison finding too
		HTTP:     &fakeHTTP{err: timeoutErr{}},
		Clock:    fixedClock(),
	}
	d := New(fixedSaltConfig(), deps)
	report := d.Run(context.Background(), snap)

	out, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, secret := range raw {
		if strings.Contains(s, secret) {
			t.Errorf("raw value %q leaked into the report:\n%s", secret, s)
		}
	}
	// Sanity: the report should still be substantive (findings were produced).
	if !strings.Contains(s, `"findings"`) || report.Summary.TotalFindings == 0 {
		t.Fatalf("expected a non-empty report, got %s", s)
	}
	// And it must remain valid JSON.
	var check map[string]any
	if err := json.Unmarshal(out, &check); err != nil {
		t.Fatalf("redacted report is not valid JSON: %v", err)
	}
	if check["schema"] != "ratelmesh.diagnose.report/v2" || reportSchema != "ratelmesh.diagnose.report/v2" {
		t.Fatalf("unexpected schema %v", check["schema"])
	}
}

func TestReportRedactsEvenAcrossIndent(t *testing.T) {
	snap, raw := secretSnapshot()
	d := New(fixedSaltConfig(), Deps{Dialer: alwaysFailDialer{}, Resolver: fakeResolver{addrs: addrs("8.8.8.8")}, HTTP: &fakeHTTP{err: timeoutErr{}}, Clock: fixedClock()})
	report := d.Run(context.Background(), snap)

	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range raw {
		if strings.Contains(string(out), secret) {
			t.Errorf("indented marshal leaked %q", secret)
		}
	}
}

func TestReportHandBuiltStillScrubsPatterns(t *testing.T) {
	// A Report assembled without a run redactor must still scrub via patterns.
	rep := Report{
		Schema:   reportSchema,
		Findings: []Finding{{Code: CodeDNSOK, Severity: SeverityOK, Probe: ProbeDNS, Summary: "resolved to 8.8.8.8", Evidence: map[string]string{"ip": "192.168.9.9"}}},
	}
	out, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, absent := range []string{"8.8.8.8", "192.168.9.9"} {
		if strings.Contains(s, absent) {
			t.Errorf("hand-built report leaked %q: %s", absent, s)
		}
	}
}

func TestWireGuardInterfaceIsTokenizedBeforeReportSharing(t *testing.T) {
	const interfaceName = "alice-corp-vpn0"
	snap := Snapshot{WireGuard: WireGuardState{Interface: interfaceName, Up: false}}
	cfg := fixedSaltConfig()
	report := New(cfg, permissiveDeps(fixedClock()), WithProbes(wireGuardProbe{})).
		Run(context.Background(), snap)
	out, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), interfaceName) {
		t.Fatalf("raw interface name leaked into report: %s", out)
	}
	if !strings.Contains(string(out), "[redacted:interface:") {
		t.Fatalf("interface token missing from report: %s", out)
	}

	again, err := json.Marshal(New(cfg, permissiveDeps(fixedClock()), WithProbes(wireGuardProbe{})).
		Run(context.Background(), snap))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(again) {
		t.Fatalf("fixed-salt interface tokenization is not deterministic:\n%s\n%s", out, again)
	}
}

func TestInterfaceTokenDoesNotBecomeGlobalSubstringReplacement(t *testing.T) {
	r := NewRedactor([]byte("fixed-test-salt"))
	token := r.tokenIdentifier("interface", "a")
	if token == "a" || !strings.HasPrefix(token, "[redacted:interface:") {
		t.Fatalf("one-character interface was not tokenized: %q", token)
	}
	if got := r.String("data path remains readable"); got != "data path remains readable" {
		t.Fatalf("interface tokenization polluted unrelated report text: %q", got)
	}
}

func TestSnapshotInterfaceTokenizationCoversAllSources(t *testing.T) {
	const (
		sharedName = "shared-interface"
		routeName  = "route-only"
	)
	original := Snapshot{
		WireGuard: WireGuardState{Interface: sharedName},
		Addresses: []InterfaceAddr{
			{Interface: sharedName},
			{Interface: ""},
		},
		Routes: []Route{
			{Interface: sharedName},
			{Interface: routeName},
			{Interface: ""},
		},
	}
	redactor := NewRedactor([]byte("fixed-test-salt"))
	got := original.tokenizedInterfaces(redactor)
	again := original.tokenizedInterfaces(redactor)

	sharedToken := got.WireGuard.Interface
	if sharedToken == "" || sharedToken == sharedName ||
		got.Addresses[0].Interface != sharedToken ||
		got.Routes[0].Interface != sharedToken {
		t.Fatalf("equal interface names did not map to one opaque token: %+v", got)
	}
	if got.Routes[1].Interface == routeName || got.Routes[1].Interface == sharedToken {
		t.Fatalf("distinct route interface was not independently tokenized: %+v", got.Routes)
	}
	if got.Addresses[1].Interface != "" || got.Routes[2].Interface != "" {
		t.Fatalf("empty interface names must remain empty: %+v %+v", got.Addresses, got.Routes)
	}
	if got.WireGuard.Interface != again.WireGuard.Interface ||
		got.Routes[1].Interface != again.Routes[1].Interface {
		t.Fatalf("interface tokenization is not deterministic: %+v %+v", got, again)
	}
	if original.WireGuard.Interface != sharedName ||
		original.Addresses[0].Interface != sharedName ||
		original.Routes[1].Interface != routeName {
		t.Fatalf("tokenization mutated the caller's snapshot: %+v", original)
	}
}

// TestReportRedactsConfigNetworkIdentifiers proves the operator-overridable
// connectivity targets and DNS query name are registered as per-run known
// secrets and never leak. The structural pattern scrubber catches bare IP
// literals but NOT a bare hostname or a domain:port with no scheme, so without
// this registration an internal target would survive verbatim in a probe's
// evidence or error text. Stable probe labels/codes must still survive.
func TestReportRedactsConfigNetworkIdentifiers(t *testing.T) {
	const (
		dnsName  = "canary.secret-corp.internal"
		v4target = "gate4.secret-corp.internal:8443"
		v6target = "gate6.secret-corp.internal:8443"
		v4host   = "gate4.secret-corp.internal"
		v6host   = "gate6.secret-corp.internal"
	)
	cfg := fixedSaltConfig()
	cfg.ConnectivityTarget4 = v4target
	cfg.ConnectivityTarget6 = v6target
	cfg.DNS.QueryName = dnsName

	// Failing deps so ipv4/ipv6 emit unreachable findings (target evidence) and DNS
	// times out (query evidence), carrying the identifiers into the report.
	deps := Deps{
		Dialer:   alwaysFailDialer{},
		Resolver: fakeResolver{err: timeoutErr{}},
		HTTP:     &fakeHTTP{err: timeoutErr{}},
		Clock:    fixedClock(),
	}
	snap := Snapshot{
		Addresses: []InterfaceAddr{
			{Interface: "en0", Family: FamilyV4, Addr: mustAddr("198.51.100.7")},
			{Interface: "en0", Family: FamilyV6, Addr: mustAddr("2001:db8::7")},
		},
	}
	report := New(cfg, deps).Run(context.Background(), snap)
	out, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, leak := range []string{dnsName, v4target, v6target, v4host, v6host, "secret-corp.internal"} {
		if strings.Contains(s, leak) {
			t.Errorf("config network identifier %q leaked into the report:\n%s", leak, s)
		}
	}
	// The report must remain substantive and NOT over-redact stable labels/codes.
	if report.Summary.TotalFindings == 0 {
		t.Fatal("expected findings carrying the config identifiers")
	}
	for _, keep := range []string{"ipv4.unreachable", "dns.timeout", "ipv6.unreachable"} {
		if !strings.Contains(s, keep) {
			t.Errorf("stable code %q must survive redaction: %s", keep, s)
		}
	}
}

func TestReportSummary(t *testing.T) {
	t.Run("healthy is ok", func(t *testing.T) {
		d := New(fixedSaltConfig(), permissiveDeps(fixedClock()))
		report := d.Run(context.Background(), healthySnapshot())
		if !report.Summary.OK {
			t.Fatalf("healthy snapshot should be OK, worst=%v findings=%+v", report.Summary.WorstSeverity, report.Findings)
		}
		if report.Summary.WorstSeverity > SeverityInfo {
			t.Fatalf("healthy snapshot should have no warnings/criticals, got %v", report.Summary.WorstSeverity)
		}
	})
	t.Run("broken is critical", func(t *testing.T) {
		snap, _ := secretSnapshot()
		d := New(fixedSaltConfig(), Deps{Dialer: alwaysFailDialer{}, Resolver: fakeResolver{addrs: addrs("127.0.0.1")}, HTTP: &fakeHTTP{err: timeoutErr{}}, Clock: fixedClock()})
		report := d.Run(context.Background(), snap)
		if report.Summary.OK {
			t.Fatal("broken snapshot should not be OK")
		}
		if report.Summary.WorstSeverity != SeverityCritical {
			t.Fatalf("expected a critical worst severity, got %v", report.Summary.WorstSeverity)
		}
		if report.Summary.TotalFindings != len(report.Findings) {
			t.Fatal("summary total should match findings length")
		}
	})
}

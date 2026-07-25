package diagnose

// Code is a stable, machine-readable identifier for a Finding. Codes are part
// of the support-report and repair-plan contract: their string values are
// frozen and safe to match on in tooling, dashboards and repair catalogues.
// New codes may be added; existing ones must not change meaning or spelling.
//
// The naming scheme is "<probe>.<condition>", always lower-case snake within a
// dotted namespace. Every code that ships is registered in codeCatalog with a
// default Severity and a terse, English, developer-facing title (report codes
// are diagnostic, not localised end-user CLI strings).
type Code string

// Coordinator probe codes.
const (
	CodeCoordinatorOK            Code = "coordinator.ok"
	CodeCoordinatorNotConfigured Code = "coordinator.not_configured"
	CodeCoordinatorUnreachable   Code = "coordinator.unreachable"
	CodeCoordinatorTLSError      Code = "coordinator.tls_error"
	CodeCoordinatorUnhealthy     Code = "coordinator.unhealthy"
)

// Relay probe codes.
const (
	CodeRelayOK             Code = "relay.ok"
	CodeRelayNoneConfigured Code = "relay.none_configured"
	CodeRelayUnreachable    Code = "relay.unreachable"
	CodeRelayNoneReachable  Code = "relay.none_reachable"
)

// EXIT probe codes.
const (
	CodeExitOK              Code = "exit.ok"
	CodeExitNotSelected     Code = "exit.not_selected"
	CodeExitHandshakeStale  Code = "exit.handshake_stale"
	CodeExitRouteMissing    Code = "exit.route_missing"
	CodeExitEgressBlocked   Code = "exit.egress_blocked"
	CodeExitEgressNotTested Code = "exit.egress_not_tested"
)

// WireGuard probe codes.
const (
	CodeWireGuardOK              Code = "wireguard.ok"
	CodeWireGuardNotConfigured   Code = "wireguard.not_configured"
	CodeWireGuardInterfaceDown   Code = "wireguard.interface_down"
	CodeWireGuardNoPeers         Code = "wireguard.no_peers"
	CodeWireGuardHandshakeStale  Code = "wireguard.handshake_stale"
	CodeWireGuardPeerCounters    Code = "wireguard.peer_counters"
	CodeWireGuardReceiveStalled  Code = "wireguard.receive_stalled"
	CodeWireGuardCountersStalled Code = "wireguard.counters_stalled"
)

// MTU probe codes.
const (
	CodeMTUOK         Code = "mtu.ok"
	CodeMTUUnknown    Code = "mtu.unknown"
	CodeMTUProbeError Code = "mtu.probe_error"
	CodeMTUSuboptimal Code = "mtu.suboptimal"
	CodeMTUTooLow     Code = "mtu.too_low"
)

// DNS probe codes.
const (
	CodeDNSOK              Code = "dns.ok"
	CodeDNSNotConfigured   Code = "dns.not_configured"
	CodeDNSSlow            Code = "dns.slow"
	CodeDNSTimeout         Code = "dns.timeout"
	CodeDNSNoAnswer        Code = "dns.no_answer"
	CodeDNSPoisonSuspected Code = "dns.poison_suspected"
)

// IPv4 probe codes.
const (
	CodeIPv4OK          Code = "ipv4.ok"
	CodeIPv4Unavailable Code = "ipv4.unavailable"
	CodeIPv4Unreachable Code = "ipv4.unreachable"
)

// IPv6 probe codes.
const (
	CodeIPv6OK                 Code = "ipv6.ok"
	CodeIPv6Unavailable        Code = "ipv6.unavailable"
	CodeIPv6Unreachable        Code = "ipv6.unreachable"
	CodeIPv6LeakRisk           Code = "ipv6.leak_risk"
	CodeIPv6ContainmentUnknown Code = "ipv6.containment_unknown"
)

// Routes probe codes.
const (
	CodeRoutesOK                Code = "routes.ok"
	CodeRoutesDefaultMissing    Code = "routes.default_missing"
	CodeRoutesExitDefaultAbsent Code = "routes.exit_default_absent"
	CodeRoutesPhysicalFallback  Code = "routes.physical_fallback"
)

// Media (sustained video/media reachability) probe codes.
const (
	CodeMediaOK                   Code = "media.ok"
	CodeMediaNotConfigured        Code = "media.not_configured"
	CodeMediaSlow                 Code = "media.slow"
	CodeMediaIntermittent         Code = "media.intermittent"
	CodeMediaTargetUnreachable    Code = "media.target_unreachable"
	CodeMediaEvidenceInconclusive Code = "media.evidence_inconclusive"
	CodeMediaPathUnreachable      Code = "media.path_unreachable"
	CodeMediaQUICOK               Code = "media.quic_ok"
	CodeMediaQUICNotTested        Code = "media.quic_not_tested"
	CodeMediaQUICHandshakeFailed  Code = "media.quic_handshake_failed"
	CodeMediaHTTPSFallbackOK      Code = "media.https_fallback_ok"
	CodeMediaHTTPSFallbackFailed  Code = "media.https_fallback_failed"
	// CodeMediaUnreachable is retained with its v1 target-level meaning for
	// parsers of archived reports. New v2 reports emit the two explicit target
	// and path codes above instead of overloading it.
	CodeMediaUnreachable Code = "media.unreachable"
)

// Probe-framework codes, emitted by the runner rather than a specific probe.
const (
	CodeProbeError   Code = "probe.error"
	CodeProbeTimeout Code = "probe.timeout"
	CodeProbePanic   Code = "probe.panic"
)

// codeMeta is the frozen metadata for a Code.
type codeMeta struct {
	Severity Severity
	Title    string
}

// codeCatalog is the authoritative registry of every shipped Code. Anything a
// probe emits must be present here so severity and titles stay consistent and
// so tests can assert the set is complete.
var codeCatalog = map[Code]codeMeta{
	CodeCoordinatorOK:            {SeverityOK, "coordinator reachable"},
	CodeCoordinatorNotConfigured: {SeverityInfo, "coordinator endpoint not configured"},
	CodeCoordinatorUnreachable:   {SeverityWarning, "coordinator unreachable"},
	CodeCoordinatorTLSError:      {SeverityWarning, "coordinator TLS handshake failed"},
	CodeCoordinatorUnhealthy:     {SeverityWarning, "coordinator health check failed"},

	CodeRelayOK:             {SeverityOK, "relay reachable"},
	CodeRelayNoneConfigured: {SeverityInfo, "no relay configured"},
	CodeRelayUnreachable:    {SeverityWarning, "relay unreachable"},
	CodeRelayNoneReachable:  {SeverityWarning, "no configured relay is reachable"},

	CodeExitOK:              {SeverityOK, "exit healthy"},
	CodeExitNotSelected:     {SeverityInfo, "no exit selected"},
	CodeExitHandshakeStale:  {SeverityCritical, "exit WireGuard handshake is stale"},
	CodeExitRouteMissing:    {SeverityCritical, "exit selected but its route is absent"},
	CodeExitEgressBlocked:   {SeverityCritical, "exit egress reachability failed"},
	CodeExitEgressNotTested: {SeverityWarning, "exit egress reachability was not tested"},

	CodeWireGuardOK:              {SeverityOK, "WireGuard healthy"},
	CodeWireGuardNotConfigured:   {SeverityInfo, "WireGuard interface not configured"},
	CodeWireGuardInterfaceDown:   {SeverityCritical, "WireGuard interface is down"},
	CodeWireGuardNoPeers:         {SeverityWarning, "WireGuard interface has no peers"},
	CodeWireGuardHandshakeStale:  {SeverityWarning, "a WireGuard peer handshake is stale"},
	CodeWireGuardPeerCounters:    {SeverityInfo, "WireGuard peer counter snapshot captured"},
	CodeWireGuardReceiveStalled:  {SeverityWarning, "WireGuard transmitted traffic but received no progress"},
	CodeWireGuardCountersStalled: {SeverityWarning, "expected WireGuard traffic made no counter progress"},

	CodeMTUOK:         {SeverityOK, "path MTU healthy"},
	CodeMTUUnknown:    {SeverityInfo, "path MTU could not be determined"},
	CodeMTUProbeError: {SeverityWarning, "active path MTU probe failed to measure"},
	CodeMTUSuboptimal: {SeverityWarning, "path MTU is below the configured link MTU"},
	CodeMTUTooLow:     {SeverityCritical, "path MTU is below the safe floor"},

	CodeDNSOK:              {SeverityOK, "DNS resolution healthy"},
	CodeDNSNotConfigured:   {SeverityInfo, "no DNS server configured"},
	CodeDNSSlow:            {SeverityInfo, "DNS resolution is slow"},
	CodeDNSTimeout:         {SeverityWarning, "DNS resolution timed out"},
	CodeDNSNoAnswer:        {SeverityWarning, "DNS query returned no answer"},
	CodeDNSPoisonSuspected: {SeverityCritical, "DNS answer looks poisoned"},

	CodeIPv4OK:          {SeverityOK, "IPv4 connectivity healthy"},
	CodeIPv4Unavailable: {SeverityInfo, "no IPv4 address available"},
	CodeIPv4Unreachable: {SeverityCritical, "IPv4 target unreachable"},

	CodeIPv6OK:                 {SeverityOK, "IPv6 connectivity healthy"},
	CodeIPv6Unavailable:        {SeverityInfo, "no IPv6 address available"},
	CodeIPv6Unreachable:        {SeverityWarning, "IPv6 target unreachable"},
	CodeIPv6LeakRisk:           {SeverityWarning, "IPv6 has a non-tunnel default route while exit is active"},
	CodeIPv6ContainmentUnknown: {SeverityInfo, "IPv6 containment could not be confirmed while exit is active"},

	CodeRoutesOK:                {SeverityOK, "routing table healthy"},
	CodeRoutesDefaultMissing:    {SeverityCritical, "no default route present"},
	CodeRoutesExitDefaultAbsent: {SeverityCritical, "exit active but tunnel default route absent"},
	CodeRoutesPhysicalFallback:  {SeverityWarning, "default route fell back to the physical link while exit is active"},

	CodeMediaOK:                   {SeverityOK, "sustained media reachability healthy"},
	CodeMediaNotConfigured:        {SeverityInfo, "no media reachability target configured"},
	CodeMediaSlow:                 {SeverityInfo, "media reachability is slow"},
	CodeMediaIntermittent:         {SeverityWarning, "media reachability is intermittent"},
	CodeMediaTargetUnreachable:    {SeverityWarning, "one media target is unreachable"},
	CodeMediaEvidenceInconclusive: {SeverityInfo, "media evidence is insufficient for a path-wide conclusion"},
	CodeMediaPathUnreachable:      {SeverityCritical, "independent media sources unanimously unreachable"},
	CodeMediaQUICOK:               {SeverityOK, "HTTP/3 TLS-over-QUIC handshake succeeded"},
	CodeMediaQUICNotTested:        {SeverityInfo, "HTTP/3 capability was not tested"},
	CodeMediaQUICHandshakeFailed:  {SeverityInfo, "HTTP/3 TLS-over-QUIC handshake was not established"},
	CodeMediaHTTPSFallbackOK:      {SeverityOK, "sustained HTTPS fallback succeeded"},
	CodeMediaHTTPSFallbackFailed:  {SeverityWarning, "sustained HTTPS fallback was not established"},
	CodeMediaUnreachable:          {SeverityCritical, "media target unreachable"},

	CodeProbeError:   {SeverityWarning, "probe failed to complete"},
	CodeProbeTimeout: {SeverityWarning, "probe timed out"},
	CodeProbePanic:   {SeverityWarning, "probe panicked"},
}

// Known reports whether c is a registered code.
func (c Code) Known() bool {
	_, ok := codeCatalog[c]
	return ok
}

// DefaultSeverity returns the registered severity for c, or SeverityInfo if c
// is unknown (unknown codes are never produced by shipped probes, but callers
// building findings by hand get a safe, non-alarming default).
func (c Code) DefaultSeverity() Severity {
	if m, ok := codeCatalog[c]; ok {
		return m.Severity
	}
	return SeverityInfo
}

// Title returns the terse developer-facing description registered for c.
func (c Code) Title() string {
	if m, ok := codeCatalog[c]; ok {
		return m.Title
	}
	return string(c)
}

// AllCodes returns every registered code. The result is freshly allocated and
// unordered; callers that need determinism should sort it.
func AllCodes() []Code {
	out := make([]Code, 0, len(codeCatalog))
	for c := range codeCatalog {
		out = append(out, c)
	}
	return out
}

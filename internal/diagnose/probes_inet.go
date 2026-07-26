package diagnose

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// dnsProbe resolves a stable public name and inspects the answer for timeouts,
// empty results, slowness and signs of poisoning (a public name resolving to a
// loopback/private/mesh address, the classic GFW blackhole).
type dnsProbe struct{}

func (dnsProbe) ID() ProbeID { return ProbeDNS }

func (dnsProbe) Run(ctx context.Context, env *Env) ProbeResult {
	res := ProbeResult{Probe: ProbeDNS}
	if env.Deps.Resolver == nil {
		res.add(newFinding(ProbeDNS, CodeDNSNotConfigured,
			"no resolver is available to test DNS", nil))
		return res
	}
	name := env.Config.DNS.QueryName

	start := env.Clock.Now()
	addrs, err := env.Deps.Resolver.LookupNetIP(ctx, "ip", name)
	elapsed := env.Clock.Now().Sub(start)

	if err != nil {
		code := CodeDNSNoAnswer
		if isTimeout(err) {
			code = CodeDNSTimeout
		}
		res.add(newFinding(ProbeDNS, code,
			fmt.Sprintf("resolving %q failed", name),
			map[string]string{"query": name, "error_class": safeErrorClass(err)}))
		return res
	}
	if len(addrs) == 0 {
		res.add(newFinding(ProbeDNS, CodeDNSNoAnswer,
			fmt.Sprintf("resolving %q returned no addresses", name),
			map[string]string{"query": name}))
		return res
	}

	if class, suspect := poisonClass(addrs); suspect {
		res.add(newFinding(ProbeDNS, CodeDNSPoisonSuspected,
			fmt.Sprintf("public name %q resolved to a %s address, which suggests poisoning or a blackhole", name, class),
			map[string]string{"query": name, "class": class}))
	} else {
		res.add(newFinding(ProbeDNS, CodeDNSOK,
			fmt.Sprintf("resolved %q to %d address(es)", name, len(addrs)),
			map[string]string{"query": name, "answers": fmt.Sprint(len(addrs))}))
	}
	if elapsed > env.Config.DNS.SlowThreshold {
		res.add(newFinding(ProbeDNS, CodeDNSSlow,
			fmt.Sprintf("DNS resolution took %s", elapsed.Round(time.Millisecond)),
			map[string]string{"query": name, "elapsed_ms": fmt.Sprint(elapsed.Milliseconds())}))
	}
	return res
}

// poisonClass inspects every answer and returns the coarse class of the first
// suspicious one. A single unsafe answer is enough to make a public query
// suspicious: clients may select any address from a mixed RR set, so a public
// first answer must not hide a later loopback/private/mesh address.
func poisonClass(addrs []netip.Addr) (string, bool) {
	if len(addrs) == 0 {
		return "", false
	}
	for _, addr := range addrs {
		if !addr.IsValid() {
			return "invalid", true
		}
		class := classifyIP(addr)
		switch class {
		case "loopback", "unspecified", "mesh", "private", "linklocal", "multicast":
			return class, true
		}
	}
	return classifyIP(addrs[0]), false
}

// ipv4Probe confirms IPv4 egress reachability.
type ipv4Probe struct{}

func (ipv4Probe) ID() ProbeID { return ProbeIPv4 }

func (ipv4Probe) Run(ctx context.Context, env *Env) ProbeResult {
	return runFamily(ctx, env, FamilyV4, "tcp4", env.Config.ConnectivityTarget4,
		CodeIPv4Unavailable, CodeIPv4Unreachable, CodeIPv4OK)
}

// ipv6Probe confirms IPv6 egress reachability and flags an IPv6 leak: a
// non-tunnel IPv6 default route while an exit is active would let v6 traffic
// escape the tunnel (a known kill-switch gap).
type ipv6Probe struct{}

func (ipv6Probe) ID() ProbeID { return ProbeIPv6 }

func (ipv6Probe) Run(ctx context.Context, env *Env) ProbeResult {
	res := runFamily(ctx, env, FamilyV6, "tcp6", env.Config.ConnectivityTarget6,
		CodeIPv6Unavailable, CodeIPv6Unreachable, CodeIPv6OK)

	// Only evaluate IPv6 containment when the host actually has an IPv6 address:
	// without one, IPv6 cannot leak. Coverage is judged by route specificity, so
	// a physical ::/0 sitting underneath complete tunnel/blackhole ::/1 + 8000::/1
	// coverage is contained (not a leak), an intentional blackhole half is
	// accepted, and only a genuine physical escape is flagged. An inconclusive
	// observation is reported without claiming safety.
	if env.Snapshot.ExitActive && hasFamily(env.Snapshot.Addresses, FamilyV6) {
		switch defaultCoverage(env.Snapshot.Routes, FamilyV6) {
		case coveragePhysicalEscape:
			res.add(newFinding(ProbeIPv6, CodeIPv6LeakRisk,
				"an IPv6 default route bypasses the tunnel while the exit is active", nil))
		case coverageUnknown:
			res.add(newFinding(ProbeIPv6, CodeIPv6ContainmentUnknown,
				"IPv6 containment could not be confirmed: no complete tunnel or blackhole IPv6 default route was observed while the exit is active", nil))
		case coverageContained:
			// Tunnel/blackhole routes fully own IPv6; nothing to flag.
		}
	}
	return res
}

// runFamily performs a family-specific connectivity check: unavailable if the
// snapshot has no address of that family, unreachable if the target does not
// connect, healthy otherwise.
func runFamily(ctx context.Context, env *Env, fam AddressFamily, network, target string, unavailable, unreachable, ok Code) ProbeResult {
	id := ProbeIPv4
	if fam == FamilyV6 {
		id = ProbeIPv6
	}
	res := ProbeResult{Probe: id}

	if !hasFamily(env.Snapshot.Addresses, fam) {
		res.add(newFinding(id, unavailable,
			fmt.Sprintf("no IPv%d address is available", int(fam)), nil))
		return res
	}

	conn, err := dialBounded(ctx, env, network, target)
	if err != nil {
		res.add(newFinding(id, unreachable,
			fmt.Sprintf("could not establish an IPv%d connection to the reachability target", int(fam)),
			map[string]string{"target": target, "error_class": safeErrorClass(err)}))
		return res
	}
	_ = conn.Close()
	res.add(newFinding(id, ok,
		fmt.Sprintf("IPv%d connectivity confirmed", int(fam)),
		map[string]string{"target": target}))
	return res
}

// mediaProbe measures sustained reachability to media/video targets by making a
// short burst of ranged reads and scoring the success ratio and mean latency.
type mediaProbe struct{}

func (mediaProbe) ID() ProbeID { return ProbeMedia }

func (mediaProbe) Run(ctx context.Context, env *Env) ProbeResult {
	res := ProbeResult{Probe: ProbeMedia}
	targets := uniqueMediaTargets(env.Snapshot.MediaTargets)
	if len(targets) == 0 {
		res.add(newFinding(ProbeMedia, CodeMediaNotConfigured,
			"no media reachability target is configured", nil))
		return res
	}
	mc := env.Config.Media
	completed, unreachable := 0, 0
	failedSources := make(map[string]struct{})
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		quicFinding, quicComplete := probeMediaQUIC(ctx, env, t, mc)
		if !quicComplete {
			break
		}
		res.add(quicFinding)

		sample := sampleMedia(ctx, env, t, mc)
		if !sample.complete {
			break
		}
		completed++
		if sample.unreachable {
			unreachable++
			if source, ok := mediaEvidenceSource(t.EvidenceSource); ok {
				failedSources[source] = struct{}{}
			}
		}
		res.add(sample.finding)
		res.add(httpsFallbackFinding(t, sample))
	}

	switch {
	case completed == len(targets) && unreachable == completed && len(failedSources) >= 2:
		res.add(newFinding(ProbeMedia, CodeMediaPathUnreachable,
			fmt.Sprintf("all %d media targets across %d independent sources were unreachable",
				completed, len(failedSources)),
			map[string]string{
				"completed_targets":   fmt.Sprint(completed),
				"failed_targets":      fmt.Sprint(unreachable),
				"independent_sources": fmt.Sprint(len(failedSources)),
			}))
	case completed > 0 && (completed < len(targets) || completed == 1 || unreachable > 0):
		res.add(newFinding(ProbeMedia, CodeMediaEvidenceInconclusive,
			"media observations do not establish a path-wide failure",
			map[string]string{
				"completed_targets":   fmt.Sprint(completed),
				"failed_targets":      fmt.Sprint(unreachable),
				"independent_sources": fmt.Sprint(len(failedSources)),
			}))
	}
	return res
}

type mediaSampleResult struct {
	finding     Finding
	complete    bool
	unreachable bool
	attempts    int
	successes   int
	fallbackOK  bool
}

// probeMediaQUIC establishes a real TLS-over-QUIC handshake with ALPN h3. It
// is independent of the ranged HTTPS samples below: neither result is inferred
// from the other. A failed handshake is intentionally described as
// "not established", not "UDP blocked", because certificate, server, path and
// policy failures are observationally indistinguishable here.
func probeMediaQUIC(ctx context.Context, env *Env, target Endpoint, cfg MediaProbeConfig) (Finding, bool) {
	ev := map[string]string{"target": target.Label, "alpn": "h3", "transport": "udp"}
	if env.Deps.QUIC == nil {
		return newFinding(ProbeMedia, CodeMediaQUICNotTested,
			fmt.Sprintf("HTTP/3 capability for media target %q was not tested", target.Label), ev), true
	}
	scheme := strings.ToLower(strings.TrimSpace(target.Scheme))
	if scheme != "" && scheme != "https" {
		return newFinding(ProbeMedia, CodeMediaQUICNotTested,
			fmt.Sprintf("media target %q is not HTTPS, so HTTP/3 capability was not tested", target.Label), ev), true
	}
	if target.Host == "" {
		return newFinding(ProbeMedia, CodeMediaQUICHandshakeFailed,
			fmt.Sprintf("HTTP/3 capability for media target %q could not be established", target.Label), ev), true
	}
	port := target.Port
	if port == 0 {
		port = 443
	}
	start := env.Clock.Now()
	probeCtx, cancel := context.WithTimeout(ctx, cfg.QUICHandshakeTimeout)
	err := env.Deps.QUIC.ProbeQUIC(probeCtx, target.Host, port)
	probeErr := probeCtx.Err()
	cancel()
	if ctx.Err() != nil {
		return Finding{}, false
	}
	ev["elapsed_ms"] = fmt.Sprint(env.Clock.Now().Sub(start).Milliseconds())
	if err == nil && probeErr == nil {
		return newFinding(ProbeMedia, CodeMediaQUICOK,
			fmt.Sprintf("media target %q completed a verified HTTP/3 TLS-over-QUIC handshake", target.Label), ev), true
	}
	if probeErr != nil {
		ev["result"] = "timeout"
	} else {
		ev["result"] = "handshake_failed"
	}
	return newFinding(ProbeMedia, CodeMediaQUICHandshakeFailed,
		fmt.Sprintf("media target %q did not complete a verified HTTP/3 TLS-over-QUIC handshake", target.Label), ev), true
}

func httpsFallbackFinding(target Endpoint, sample mediaSampleResult) Finding {
	ev := map[string]string{
		"target":    target.Label,
		"transport": "tcp",
		"attempts":  fmt.Sprint(sample.attempts),
		"success":   fmt.Sprint(sample.successes),
	}
	if sample.fallbackOK {
		return newFinding(ProbeMedia, CodeMediaHTTPSFallbackOK,
			fmt.Sprintf("media target %q sustained the HTTPS-over-TCP fallback", target.Label), ev)
	}
	return newFinding(ProbeMedia, CodeMediaHTTPSFallbackFailed,
		fmt.Sprintf("media target %q did not establish a sustained HTTPS-over-TCP fallback", target.Label), ev)
}

// sampleMedia runs the sustained burst against a single target. A parent
// cancellation makes the sample incomplete, not failed: the runner owns the
// timeout finding and must not turn cancellation into path-failure evidence.
func sampleMedia(ctx context.Context, env *Env, t Endpoint, mc MediaProbeConfig) mediaSampleResult {
	url := endpointURL(t)
	attempts, successes := 0, 0
	var total time.Duration
	for i := 0; i < mc.Samples; i++ {
		if ctx.Err() != nil {
			return mediaSampleResult{}
		}
		attempts++
		start := env.Clock.Now()
		reqCtx, cancel := context.WithTimeout(ctx, mc.RequestTimeout)
		status, read, err := fetchMediaSample(reqCtx, env, url, mediaReadLimit)
		cancel()
		if ctx.Err() != nil {
			return mediaSampleResult{}
		}
		total += env.Clock.Now().Sub(start)
		// A sample counts only when a documented media status actually streamed a
		// bounded, non-empty payload without a read error — not merely because the
		// status line was 2xx/3xx. This is what separates "the page opened" from
		// "the video played".
		if mediaSampleOK(status, read, err) {
			successes++
		}
		if i < mc.Samples-1 && !sleepCtx(ctx, mc.Interval) {
			return mediaSampleResult{}
		}
	}

	ev := map[string]string{
		"target":   t.Label,
		"attempts": fmt.Sprint(attempts),
		"success":  fmt.Sprint(successes),
	}
	if attempts == 0 {
		return mediaSampleResult{}
	}
	ratio := float64(successes) / float64(attempts)
	mean := total / time.Duration(attempts)
	ev["success_ratio"] = fmt.Sprintf("%.2f", ratio)
	ev["mean_ms"] = fmt.Sprint(mean.Milliseconds())

	switch {
	case successes == 0:
		return mediaSampleResult{
			finding: newFinding(ProbeMedia, CodeMediaTargetUnreachable,
				fmt.Sprintf("media target %q was unreachable across %d samples", t.Label, attempts), ev),
			complete:    true,
			unreachable: true,
			attempts:    attempts,
			successes:   successes,
		}
	case ratio < mc.MinSuccessRatio:
		return mediaSampleResult{
			finding: newFinding(ProbeMedia, CodeMediaIntermittent,
				fmt.Sprintf("media target %q was intermittent (%d/%d samples)", t.Label, successes, attempts), ev),
			complete:  true,
			attempts:  attempts,
			successes: successes,
		}
	case mean > mc.SlowThreshold:
		return mediaSampleResult{
			finding: newFinding(ProbeMedia, CodeMediaSlow,
				fmt.Sprintf("media target %q is reachable but slow (mean %s)", t.Label, mean.Round(time.Millisecond)), ev),
			complete:   true,
			attempts:   attempts,
			successes:  successes,
			fallbackOK: true,
		}
	default:
		return mediaSampleResult{
			finding: newFinding(ProbeMedia, CodeMediaOK,
				fmt.Sprintf("media target %q is reachable (%d/%d samples)", t.Label, successes, attempts), ev),
			complete:   true,
			attempts:   attempts,
			successes:  successes,
			fallbackOK: true,
		}
	}
}

// uniqueMediaTargets returns one stable representative for each actual HTTP
// endpoint. Whether two endpoints are independent is determined separately by
// a trusted EvidenceSource, never by DNS text.
func uniqueMediaTargets(targets []Endpoint) []Endpoint {
	type aggregate struct {
		representative Endpoint
		source         string
		sourceTrusted  bool
	}
	byKey := make(map[string]aggregate, len(targets))
	for _, target := range targets {
		key := mediaEndpointKey(target)
		source, sourceTrusted := mediaEvidenceSource(target.EvidenceSource)
		current, ok := byKey[key]
		if !ok {
			byKey[key] = aggregate{
				representative: target,
				source:         source,
				sourceTrusted:  sourceTrusted,
			}
			continue
		}
		if mediaEndpointDisplayKey(target) < mediaEndpointDisplayKey(current.representative) {
			current.representative = target
		}
		current.sourceTrusted = current.sourceTrusted && sourceTrusted && current.source == source
		byKey[key] = current
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	unique := make([]Endpoint, 0, len(keys))
	for _, key := range keys {
		current := byKey[key]
		if current.sourceTrusted {
			current.representative.EvidenceSource = current.source
		} else {
			// A duplicate endpoint with missing, malformed, or conflicting
			// source metadata cannot count as independent path evidence. Clear
			// it regardless of which duplicate supplied the display fields.
			current.representative.EvidenceSource = ""
		}
		unique = append(unique, current.representative)
	}
	return unique
}

func mediaEndpointKey(endpoint Endpoint) string {
	scheme := strings.ToLower(strings.TrimSpace(endpoint.Scheme))
	if scheme == "" {
		scheme = "https"
	}
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(endpoint.Host)), ".")
	unbracketed := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if addr, err := netip.ParseAddr(unbracketed); err == nil {
		host = addr.Unmap().String()
	}
	port := endpoint.Port
	if port == 0 {
		switch scheme {
		case "http":
			port = 80
		case "https":
			port = 443
		}
	}
	path := endpoint.HealthPath
	if path == "" {
		path = "/"
	}
	return strings.Join([]string{scheme, host, strconv.Itoa(port), path}, "\x00")
}

func mediaEndpointDisplayKey(endpoint Endpoint) string {
	return strings.Join([]string{
		endpoint.Label,
		strings.ToLower(strings.TrimSpace(endpoint.Scheme)),
		strings.ToLower(strings.TrimSpace(endpoint.Host)),
		strconv.Itoa(endpoint.Port),
		endpoint.HealthPath,
	}, "\x00")
}

func mediaEvidenceSource(raw string) (string, bool) {
	source := strings.ToLower(strings.TrimSpace(raw))
	if len(source) == 0 || len(source) > 64 {
		return "", false
	}
	for _, r := range source {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == '-' {
			continue
		}
		return "", false
	}
	return source, true
}

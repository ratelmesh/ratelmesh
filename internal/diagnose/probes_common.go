package diagnose

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"
)

// Sentinel errors for missing injected capabilities. A probe that needs a
// capability the daemon did not supply degrades to an informational finding
// rather than failing the whole run.
var (
	errNoDialer = errors.New("diagnose: no dialer configured")
	errNoHTTP   = errors.New("diagnose: no HTTP client configured")
)

// mediaReadLimit bounds how many bytes the media probe pulls per sample so a
// "sustained reachability" check streams a real chunk without unbounded reads.
const mediaReadLimit = 64 << 10

// minMediaSampleBytes is the smallest payload that counts as a real, *sustained*
// media transfer. It exists to reject two failure modes that a healthy-looking
// status line hides:
//
//   - the "webpage opens but the video never plays" case — a 200/206 whose body
//     is empty (a zero-byte or 204-style response) transferred no media at all;
//   - the "connection carries a trickle then stalls" case — a 200/206 that
//     streams only a few bytes and then EOFs cleanly. A single byte, or a few
//     kilobytes, proves the socket opened but not that the path can actually
//     carry a media stream; a censor's tarpit or a broken CDN edge routinely
//     serves a tiny clean-EOF body.
//
// Requiring a meaningful fraction of mediaReadLimit — half of the 64 KiB window,
// i.e. 32 KiB — means a sample counts only when the path sustained a real chunk,
// not merely a handshake. The read is still capped by mediaReadLimit so nothing
// is unbounded.
//
// Endpoint contract: a configured media canary (Snapshot.MediaTargets, or an
// exit EgressCanary used as a media target) MUST answer a ranged GET of
// "bytes=0-65535" — or a plain GET when it ignores Range — with HTTP 200 or 206
// and a body of at least minMediaSampleBytes. A canary that serves a smaller
// object cannot be distinguished from a stalled path and will score as
// unreachable/intermittent, so canaries must point at an object of at least
// 32 KiB.
const minMediaSampleBytes = 32 << 10

// dialBounded dials through the injected Dialer under a per-dial timeout that is
// itself capped by ctx (the probe deadline). It returns errNoDialer if no
// dialer was injected.
func dialBounded(ctx context.Context, env *Env, network, address string) (net.Conn, error) {
	if env.Deps.Dialer == nil {
		return nil, errNoDialer
	}
	dctx, cancel := context.WithTimeout(ctx, env.Config.DialTimeout)
	defer cancel()
	return env.Deps.Dialer.DialContext(dctx, network, address)
}

// endpointHostPort renders host:port for e, applying defPort when e sets none.
func endpointHostPort(e Endpoint, defPort int) string {
	port := e.Port
	if port == 0 {
		port = defPort
	}
	return net.JoinHostPort(e.Host, strconv.Itoa(port))
}

// endpointURL builds an absolute URL for an application-level check of e.
func endpointURL(e Endpoint) string {
	scheme := e.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := e.Host
	if e.Port != 0 {
		host = net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	}
	u := url.URL{Scheme: scheme, Host: host, Path: e.HealthPath}
	return u.String()
}

// httpGetDrain performs a bounded HTTP GET, reads up to limit bytes of the body
// (so a media sample exercises real transfer), and returns the status code and
// how many bytes were read. It returns errNoHTTP if no client was injected.
func httpGetDrain(ctx context.Context, env *Env, rawURL string, limit int64) (status int, read int64, err error) {
	if env.Deps.HTTP == nil {
		return 0, 0, errNoHTTP
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, 0, err
	}
	resp, err := env.Deps.HTTP.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
	return resp.StatusCode, n, nil
}

// fetchMediaSample performs a bounded, ranged GET against a media target and
// reports the status, how many payload bytes actually transferred, and any
// error — including a body read that fails mid-stream. Unlike httpGetDrain it
// propagates the read error, because for a media check a healthy-looking status
// line is not proof the bytes flowed: a connection that resets partway through a
// chunk means the video stalled even though the request "succeeded". The body is
// always closed, the read is capped at limit, and a Range header asks a
// well-behaved server for only a small sample (servers that ignore it simply
// return 200 and the LimitReader still bounds the read).
func fetchMediaSample(ctx context.Context, env *Env, rawURL string, limit int64) (status int, read int64, err error) {
	if env.Deps.HTTP == nil {
		return 0, 0, errNoHTTP
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, 0, err
	}
	if limit > 0 {
		req.Header.Set("Range", "bytes=0-"+strconv.FormatInt(limit-1, 10))
	}
	resp, err := env.Deps.HTTP.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	// io.Copy returns nil at EOF; a genuine mid-stream failure surfaces as a
	// non-nil error here and is propagated so the caller can fail the sample.
	n, rerr := io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
	return resp.StatusCode, n, rerr
}

// mediaSampleOK reports whether one media sample proves a real, sustained media
// transfer. The only success is a documented media status — 200 OK (full body)
// or 206 Partial Content (a served range) — that streamed at least
// minMediaSampleBytes with no read error. A transport error, an undocumented
// status (a redirect, a 204 No Content, a 4xx/5xx), a zero-byte body, a
// short/truncated body that EOFs cleanly below the threshold, or a
// mid-stream-truncated body all count as a failed transfer even when the HTTP
// status alone looked benign.
func mediaSampleOK(status int, read int64, err error) bool {
	if err != nil {
		return false
	}
	switch status {
	case http.StatusOK, http.StatusPartialContent:
		return read >= minMediaSampleBytes
	default:
		return false
	}
}

// sleepCtx waits d, or returns false early if ctx is cancelled. A non-positive
// d is a no-op that still reports the context state, so tests can set the media
// interval to zero and run instantly.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// isTimeout reports whether err is a context deadline/cancellation or a net
// timeout, so probes can distinguish "timed out" from "refused/no answer".
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var nerr net.Error
	if errors.As(err, &nerr) {
		return nerr.Timeout()
	}
	return false
}

// hasFamily reports whether the snapshot has a usable, non-local address of the
// given family. Loopback, unspecified, multicast, and link-local-only addresses
// do not establish Internet-family availability: every normal host has loopback
// addresses, and treating ::1 as IPv6 connectivity makes an IPv4-only host look
// dual-stack.
func hasFamily(addrs []InterfaceAddr, fam AddressFamily) bool {
	for _, a := range addrs {
		if interfaceAddressSupportsFamily(a, fam) {
			return true
		}
	}
	return false
}

// interfaceAddressSupportsFamily validates both the producer's family tag and
// the address itself. IsGlobalUnicast includes private/CGNAT addresses that can
// reach the Internet through NAT, while excluding loopback, unspecified,
// multicast, and link-local addresses that cannot prove family availability.
func interfaceAddressSupportsFamily(a InterfaceAddr, fam AddressFamily) bool {
	if !a.Addr.IsValid() || !a.Addr.IsGlobalUnicast() {
		return false
	}
	switch fam {
	case FamilyV4:
		return a.Family == FamilyV4 && a.Addr.Is4()
	case FamilyV6:
		return a.Family == FamilyV6 && a.Addr.Is6()
	default:
		return false
	}
}

// Default-route coverage analysis.
//
// RatelMesh installs a "0.0.0.0/1 + 128.0.0.0/1" (or the ::/1 + 8000::/1 v6
// equivalent) split so the tunnel owns the whole address space by longest-prefix
// match without deleting the physical default, which stays for endpoint
// recovery. Effective coverage therefore depends on route *specificity*, not on
// which routes merely coexist: a physical default is a leak only when no
// complete more-specific tunnel/blackhole coverage exists. The analysis is
// deliberately fail-closed — it reports coverageUnknown rather than "safe"
// whenever it cannot observe complete containment.

// routeCoverage is the effective disposition of a family's default space.
type routeCoverage int

const (
	// coverageUnknown means no conclusive observation: neither complete
	// tunnel/blackhole coverage nor a definite physical escape. It must never be
	// reported as safe.
	coverageUnknown routeCoverage = iota
	// coverageContained means the tunnel (and/or intentional blackhole routes)
	// fully own the default space, so no traffic escapes to a physical link.
	coverageContained
	// coveragePhysicalEscape means a physical route actually carries part of the
	// default space (a genuine leak).
	coveragePhysicalEscape
)

// canonical default-scope prefixes per family. The /1 halves are matched by
// exact prefix (not by count) so duplicate halves cannot satisfy coverage.
var (
	v4LowHalf  = netip.MustParsePrefix("0.0.0.0/1")
	v4HighHalf = netip.MustParsePrefix("128.0.0.0/1")
	v6LowHalf  = netip.MustParsePrefix("::/1")
	v6HighHalf = netip.MustParsePrefix("8000::/1")
)

// halfPrefixes returns the two /1 halves that split the default route for fam.
func halfPrefixes(fam AddressFamily) (low, high netip.Prefix) {
	if fam == FamilyV6 {
		return v6LowHalf, v6HighHalf
	}
	return v4LowHalf, v4HighHalf
}

// defaultPrefix returns the full default prefix (/0) for fam.
func defaultPrefix(fam AddressFamily) netip.Prefix {
	if fam == FamilyV6 {
		return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
}

// routeFamily returns the address family a route's destination belongs to.
func routeFamily(r Route) AddressFamily {
	if r.Destination.Addr().Is4() {
		return FamilyV4
	}
	return FamilyV6
}

// dispositionAt inspects every route whose destination is exactly target within
// fam and reports whether a safe (tunnel/blackhole) route, a physical route, an
// unrecognised-kind route, or any route at all is present at that exact prefix.
func dispositionAt(routes []Route, fam AddressFamily, target netip.Prefix) (safe, physical, unknown, present bool) {
	tm := target.Masked()
	for _, r := range routes {
		if routeFamily(r) != fam {
			continue
		}
		if r.Destination.Masked() != tm {
			continue
		}
		present = true
		switch r.effectiveKind() {
		case RouteKindTunnel, RouteKindBlackhole:
			safe = true
		case RouteKindPhysical:
			physical = true
		default:
			// RouteKindUnknown (a non-empty, unrecognised producer kind). The route
			// IS present at this exact prefix, so by longest-prefix match the kernel
			// forwards matching traffic through it — to a disposition we cannot
			// classify as either containment or a physical escape. Record it as an
			// unknown presence so coverageAt makes THIS (more-specific) prefix
			// decisively unknown; a garbage kind must never defer to a less-specific
			// safe default and thereby masquerade as contained.
			unknown = true
		}
	}
	return safe, physical, unknown, present
}

// coverageAt classifies the effective disposition observed at one exact prefix
// and reports whether that observation is decisive. Ordering is fail-closed:
//   - a tunnel/blackhole route AND a physical route at the same exact prefix is
//     ambiguous (we lack the metric/priority to know which the kernel prefers),
//     so it is decisively coverageUnknown rather than assumed-safe;
//   - a physical route alone is a definite escape;
//   - an unrecognised-kind route present (with no physical route) is decisively
//     coverageUnknown: it is a real, more-specific route to an unclassifiable
//     disposition, so it must NOT fall through to a less-specific safe /0 — that
//     fallback is exactly how a garbage kind could forge a contained verdict. A
//     safe route coexisting with the unknown one does not rescue it: the pairing
//     is just as ambiguous as safe+physical;
//   - a tunnel/blackhole route alone contains the prefix.
//
// Only a prefix with no route at all is not decisive, so a less-specific prefix
// may then speak.
func coverageAt(routes []Route, fam AddressFamily, target netip.Prefix) (cov routeCoverage, decisive bool) {
	safe, physical, unknown, present := dispositionAt(routes, fam, target)
	if !present {
		return coverageUnknown, false
	}
	switch {
	case safe && physical:
		return coverageUnknown, true
	case physical:
		return coveragePhysicalEscape, true
	case unknown:
		return coverageUnknown, true
	case safe:
		return coverageContained, true
	default:
		return coverageUnknown, false
	}
}

// combineCoverage aggregates the effective coverage of two disjoint sibling
// subspaces into the coverage of their union. It is the join of the lattice
//
//	coverageContained < coverageUnknown < coveragePhysicalEscape
//
// so a definite physical escape anywhere in the union dominates (a genuine leak
// must always surface), an inconclusive subspace keeps the union inconclusive,
// and the union is contained only when BOTH siblings are wholly contained. This
// ordering guarantees a leaking subtree can never be reported as routes.ok.
func combineCoverage(a, b routeCoverage) routeCoverage {
	if a == coveragePhysicalEscape || b == coveragePhysicalEscape {
		return coveragePhysicalEscape
	}
	if a == coverageUnknown || b == coverageUnknown {
		return coverageUnknown
	}
	return coverageContained
}

// childPrefixes splits scope (assumed already masked) into its two immediate
// more-specific halves — the /(n+1) subtree whose next bit is 0 and the one
// whose next bit is 1 — covering scope exactly and disjointly. It reports
// ok=false for a host prefix (/32 or /128) that cannot be split further.
func childPrefixes(scope netip.Prefix) (low, high netip.Prefix, ok bool) {
	addr := scope.Addr()
	b := scope.Bits()
	if b < 0 || b >= addr.BitLen() {
		return netip.Prefix{}, netip.Prefix{}, false
	}
	// scope is masked, so bit b of addr is already 0: the low child is simply
	// scope re-widened by one bit. The high child sets bit b to 1.
	low = netip.PrefixFrom(addr, b+1).Masked()
	high = netip.PrefixFrom(setBit(addr, b), b+1).Masked()
	return low, high, true
}

// setBit returns addr with the bit at MSB-indexed position b set to 1, keeping
// the address family (4- vs 16-byte form) intact.
func setBit(addr netip.Addr, b int) netip.Addr {
	if addr.Is4() {
		bytes := addr.As4()
		bytes[b/8] |= 1 << (7 - uint(b%8))
		return netip.AddrFrom4(bytes)
	}
	bytes := addr.As16()
	bytes[b/8] |= 1 << (7 - uint(b%8))
	return netip.AddrFrom16(bytes)
}

// classifySpace returns the aggregate effective coverage of the address subspace
// named by scope, under longest-prefix-match semantics, given the disposition
// inherited from the nearest less-specific (ancestor) route.
//
// within is the set of routes whose masked destination lies inside scope (its
// own exact prefix or any more-specific one). The rules realised here:
//
//   - A decisive route at exactly scope (via coverageAt) is more specific than
//     any ancestor and so replaces the inherited disposition for this subtree —
//     a more-specific physical overrides a safe parent (and vice versa), and an
//     unrecognised/ambiguous kind makes the whole subtree decisively unknown.
//   - Uncovered portions of scope inherit that effective disposition unchanged,
//     so a physical parent keeps leaking wherever no safe child covers it, and a
//     space with no ancestor route at all stays coverageUnknown (fail-closed).
//   - Where more-specific routes exist, scope is split into its two halves and
//     each is classified independently; two children can therefore jointly cover
//     — and override — a parent, while combineCoverage keeps any leaking half.
//
// Recursion depth is bounded by the address bit length (≤128), and the routes
// are partitioned between the halves at each level, so the work is O(routes ×
// bitlen) without enumerating addresses and without unbounded recursion.
func classifySpace(scope netip.Prefix, fam AddressFamily, within []Route, inherited routeCoverage) routeCoverage {
	eff := inherited
	if cov, decisive := coverageAt(within, fam, scope); decisive {
		eff = cov
	}

	var deeper []Route
	for _, r := range within {
		if r.Destination.Bits() > scope.Bits() {
			deeper = append(deeper, r)
		}
	}
	if len(deeper) == 0 {
		// No more-specific route: the whole subspace resolves to eff.
		return eff
	}

	low, high, ok := childPrefixes(scope)
	if !ok {
		// A host prefix cannot have anything more specific; deeper is spurious.
		return eff
	}
	var lowWithin, highWithin []Route
	for _, r := range deeper {
		na := r.Destination.Addr()
		switch {
		case low.Contains(na):
			lowWithin = append(lowWithin, r)
		case high.Contains(na):
			highWithin = append(highWithin, r)
		}
	}
	return combineCoverage(
		classifySpace(low, fam, lowWithin, eff),
		classifySpace(high, fam, highWithin, eff),
	)
}

// routeInFamily reports whether r has a valid destination in fam. Routes with an
// invalid destination address, or one of the other family, are rejected so the
// coverage walk never mixes families or dereferences a zero prefix.
func routeInFamily(r Route, fam AddressFamily) bool {
	if !r.Destination.Addr().IsValid() {
		return false
	}
	return routeFamily(r) == fam
}

// defaultCoverage classifies the effective disposition of the ENTIRE fam address
// space under longest-prefix-match semantics and reduces it to a single verdict:
// coverageContained only when every address resolves to a tunnel/blackhole route,
// coveragePhysicalEscape when any subtree actually egresses a physical link (a
// genuine leak), and coverageUnknown otherwise (uncovered space or an ambiguous/
// unrecognised route). It never reports safe unless containment holds everywhere,
// and — crucially — a more-specific physical route (e.g. a physical /24 beneath a
// complete tunnel /1+/1 split) leaks its own subtree and is surfaced as an escape
// rather than masked by the safe parent. Invalid or wrong-family routes are
// dropped; duplicates are harmless.
func defaultCoverage(routes []Route, fam AddressFamily) routeCoverage {
	within := make([]Route, 0, len(routes))
	for _, r := range routes {
		if routeInFamily(r, fam) {
			within = append(within, r)
		}
	}
	// No ancestor route exists above /0, so uncovered space starts unknown.
	return classifySpace(defaultPrefix(fam), fam, within, coverageUnknown)
}

// presentAt reports whether any route in fam has a destination exactly equal to
// target's masked prefix. Kind is irrelevant: this is a pure presence check.
func presentAt(routes []Route, fam AddressFamily, target netip.Prefix) bool {
	tm := target.Masked()
	for _, r := range routes {
		if routeFamily(r) != fam {
			continue
		}
		if r.Destination.Masked() == tm {
			return true
		}
	}
	return false
}

// spaceCovered reports whether every address in scope is covered by SOME present
// route (of any kind) under longest-prefix match, given whether a less-specific
// ancestor route already covers the scope. Presence coverage is monotonic — a
// more-specific route can only add coverage, never remove it — so once an
// ancestor or an exact route covers scope, the whole subtree is covered. An
// uncovered scope is complete only when BOTH of its more-specific halves are
// independently covered. This is the arbitrary-prefix generalisation of the old
// "/0 or two /1 halves" rule: a /0, both /1 halves, four /2 quarters, or any
// mixed set that tiles the space all count. Recursion is bounded by the address
// bit length and the routes are partitioned between halves at each level.
func spaceCovered(scope netip.Prefix, fam AddressFamily, within []Route, inherited bool) bool {
	if inherited || presentAt(within, fam, scope) {
		return true
	}
	// Not covered at this level: a more-specific route in each half must fill it.
	var deeper []Route
	for _, r := range within {
		if r.Destination.Bits() > scope.Bits() {
			deeper = append(deeper, r)
		}
	}
	if len(deeper) == 0 {
		return false
	}
	low, high, ok := childPrefixes(scope)
	if !ok {
		return false
	}
	var lowWithin, highWithin []Route
	for _, r := range deeper {
		na := r.Destination.Addr()
		switch {
		case low.Contains(na):
			lowWithin = append(lowWithin, r)
		case high.Contains(na):
			highWithin = append(highWithin, r)
		}
	}
	return spaceCovered(low, fam, lowWithin, false) && spaceCovered(high, fam, highWithin, false)
}

// hasCompleteDefault reports whether fam's ENTIRE address space is covered by
// present routes under longest-prefix match, for ANY arbitrary combination of
// prefixes that tiles the space — an exact /0, both distinct /1 halves, four /2
// quarters, and so on. A lone /1 half, duplicate copies of one half, or any set
// that leaves a gap does NOT count. This is a presence-by-specificity check, not
// a leak analysis; kind is deliberately ignored here (defaultCoverage handles
// tunnel/physical disposition). Invalid or wrong-family routes are dropped.
func hasCompleteDefault(routes []Route, fam AddressFamily) bool {
	within := make([]Route, 0, len(routes))
	for _, r := range routes {
		if routeInFamily(r, fam) {
			within = append(within, r)
		}
	}
	return spaceCovered(defaultPrefix(fam), fam, within, false)
}

// relevantRouteFamilies returns the address families the node actually uses, in
// deterministic v4-then-v6 order, so default-route presence can be required of
// each family independently. A family is relevant when the node holds at least
// one usable, non-local interface address in it; loopback, unspecified,
// multicast and link-local-only addresses do not make a family relevant. When
// the snapshot reports no usable addresses (family membership is unknown) it
// falls back to the families that appear in the routing table. Both the address
// and the fallback path drop invalid/unknown families. When neither yields a
// family the result is empty, which the caller fails closed on.
func relevantRouteFamilies(snap Snapshot) []AddressFamily {
	var haveV4, haveV6 bool
	for _, a := range snap.Addresses {
		switch {
		case interfaceAddressSupportsFamily(a, FamilyV4):
			haveV4 = true
		case interfaceAddressSupportsFamily(a, FamilyV6):
			haveV6 = true
		}
	}
	if !haveV4 && !haveV6 {
		// No address information: scope relevance to the families present in the
		// routing table so a table with only v6 routes is judged on v6 alone.
		for _, r := range snap.Routes {
			if !r.Destination.Addr().IsValid() {
				continue
			}
			switch routeFamily(r) {
			case FamilyV4:
				haveV4 = true
			case FamilyV6:
				haveV6 = true
			}
		}
	}
	var fams []AddressFamily
	if haveV4 {
		fams = append(fams, FamilyV4)
	}
	if haveV6 {
		fams = append(fams, FamilyV6)
	}
	return fams
}

// allFamiliesHaveDefault reports whether every relevant family has a complete
// default route. It is deliberately fail-closed: an empty family set (no
// configured address and no route at all) reports false, so a wholly
// unconfigured node surfaces the missing default rather than passing by vacuous
// truth.
func allFamiliesHaveDefault(routes []Route, fams []AddressFamily) bool {
	if len(fams) == 0 {
		return false
	}
	for _, fam := range fams {
		if !hasCompleteDefault(routes, fam) {
			return false
		}
	}
	return true
}

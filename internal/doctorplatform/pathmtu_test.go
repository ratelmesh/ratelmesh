package doctorplatform

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fakePathMTURunner struct {
	thresholdPayload int
	useThreshold     bool
	resultFunc       func(payload, sample int) pathMTUProbeResult
	samples          map[int]int
	block            bool
	err              error
	specs            []commandSpec
}

func (r *fakePathMTURunner) probe(ctx context.Context, spec commandSpec) (pathMTUProbeResult, error) {
	r.specs = append(r.specs, spec)
	if r.block {
		<-ctx.Done()
		return pathMTUIndeterminate, ctx.Err()
	}
	if r.err != nil {
		return pathMTUIndeterminate, r.err
	}
	payload, payloadErr := payloadFromSpec(spec)
	if payloadErr != nil {
		return pathMTUIndeterminate, payloadErr
	}
	if r.resultFunc != nil {
		if r.samples == nil {
			r.samples = make(map[int]int)
		}
		r.samples[payload]++
		return r.resultFunc(payload, r.samples[payload]), nil
	}
	if r.useThreshold {
		if payload > r.thresholdPayload {
			return pathMTUExplicitTooLarge, nil
		}
	}
	return pathMTUFit, nil
}

type fakePathMTUResolver struct {
	addrs   []netip.Addr
	err     error
	block   bool
	calls   int
	network string
	host    string
}

type deadlinePathMTURunner struct {
	fitPayload int
	specs      []commandSpec
}

func (r *deadlinePathMTURunner) probe(ctx context.Context, spec commandSpec) (pathMTUProbeResult, error) {
	r.specs = append(r.specs, spec)
	payload, err := payloadFromSpec(spec)
	if err != nil {
		return pathMTUIndeterminate, err
	}
	if payload == r.fitPayload {
		return pathMTUFit, nil
	}
	<-ctx.Done()
	return pathMTUIndeterminate, ctx.Err()
}

func (r *fakePathMTUResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r.calls++
	r.network, r.host = network, host
	if r.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return append([]netip.Addr(nil), r.addrs...), r.err
}

func payloadFromSpec(spec commandSpec) (int, error) {
	for index, argument := range spec.args {
		if argument == "-s" || argument == "-l" {
			if index+1 >= len(spec.args) {
				return 0, errors.New("missing payload")
			}
			return strconv.Atoi(spec.args[index+1])
		}
	}
	return 0, errors.New("missing size option")
}

func TestPathMTUConservativeGridWithExplicitTooLarge(t *testing.T) {
	const low, high, threshold = 1200, 1500, 1380
	runner := &fakePathMTURunner{
		thresholdPayload: threshold - pathMTUOverhead(pathMTUV4),
		useThreshold:     true,
	}
	prober := newPathMTUProber(pathMTUPlatformLinux, runner)
	got, err := prober.ProbeMTU(context.Background(), "198.51.100.8", low, high)
	if err != nil {
		t.Fatal(err)
	}
	want := highestCandidateAtOrBelow(low, high, threshold)
	if got != want || got > threshold {
		t.Fatalf("MTU = %d, want safe grid candidate %d", got, want)
	}
	if len(runner.specs) > pathMTUMaxCommands {
		t.Fatalf("commands = %d, limit %d", len(runner.specs), pathMTUMaxCommands)
	}
	for _, spec := range runner.specs {
		if spec.path != "/usr/bin/ping" || spec.args[0] != "-4" ||
			!containsAdjacent(spec.args, "-M", "do") {
			t.Fatalf("unsafe Linux IPv4 command: %+v", spec)
		}
	}
}

func TestPathMTUWorstRangeStaysWithinCommandBudget(t *testing.T) {
	const low = 1200
	high := low + pathMTUMaxRange
	const threshold = 5000
	runner := &fakePathMTURunner{
		thresholdPayload: threshold - pathMTUOverhead(pathMTUV4),
		useThreshold:     true,
	}
	prober := newPathMTUProber(pathMTUPlatformLinux, runner)
	got, err := prober.ProbeMTU(context.Background(), "198.51.100.8", low, high)
	want := highestCandidateAtOrBelow(low, high, threshold)
	if err != nil || got != want || got > threshold {
		t.Fatalf("ProbeMTU = %d, %v", got, err)
	}
	if len(runner.specs) > pathMTUMaxCommands {
		t.Fatalf("commands = %d, limit %d", len(runner.specs), pathMTUMaxCommands)
	}
}

func TestPathMTUCandidateGridIsBoundedAndIncludesKeyPoints(t *testing.T) {
	candidates := pathMTUCandidates(1100, 1500)
	if len(candidates) > pathMTUMaxCandidates {
		t.Fatalf("candidate count = %d", len(candidates))
	}
	if candidates[0] != 1100 || candidates[len(candidates)-1] != 1500 {
		t.Fatalf("candidate endpoints = %v", candidates)
	}
	found1280 := false
	for _, candidate := range candidates {
		if candidate == 1280 {
			found1280 = true
		}
	}
	if !found1280 {
		t.Fatalf("candidate grid omitted IPv6 minimum: %v", candidates)
	}
}

func TestPathMTUHighMustPassRepeatedlyAndFinalRecheck(t *testing.T) {
	runner := &fakePathMTURunner{}
	prober := newPathMTUProber(pathMTUPlatformLinux, runner)
	got, err := prober.ProbeMTU(context.Background(), "198.51.100.8", 1200, 1500)
	if err != nil || got != 1500 {
		t.Fatalf("ProbeMTU = %d, %v", got, err)
	}
	wantCommands := len(pathMTUCandidates(1200, 1500))*pathMTUProbeSamples + pathMTUFinalSamples
	if len(runner.specs) != wantCommands {
		t.Fatalf("commands = %d, want %d", len(runner.specs), wantCommands)
	}
}

func TestPathMTUTwoOfThreeQuorumToleratesTransientLoss(t *testing.T) {
	calls := 0
	runner := &fakePathMTURunner{resultFunc: func(_ int, _ int) pathMTUProbeResult {
		calls++
		if calls%10 == 0 {
			return pathMTUIndeterminate
		}
		return pathMTUFit
	}}
	prober := newPathMTUProber(pathMTUPlatformLinux, runner)
	if mtu, err := prober.ProbeMTU(context.Background(), "198.51.100.8", 1200, 1500); err != nil || mtu != 1500 {
		t.Fatalf("ProbeMTU = %d, %v", mtu, err)
	}
}

func TestPathMTUHighLossReturnsLowerVerifiedCandidate(t *testing.T) {
	const low, high = 1200, 1500
	highPayload := high - pathMTUOverhead(pathMTUV4)
	runner := &fakePathMTURunner{resultFunc: func(payload, _ int) pathMTUProbeResult {
		if payload == highPayload {
			return pathMTUIndeterminate
		}
		return pathMTUFit
	}}
	prober := newPathMTUProber(pathMTUPlatformLinux, runner)
	candidates := pathMTUCandidates(low, high)
	want := candidates[len(candidates)-2]
	if mtu, err := prober.ProbeMTU(context.Background(), "198.51.100.8", low, high); err != nil || mtu != want {
		t.Fatalf("ProbeMTU = %d, %v; want %d", mtu, err, want)
	}
}

func TestPathMTUTimeoutScanPreservesFinalRecheckBudget(t *testing.T) {
	const low, high = 1200, 1500
	runner := &deadlinePathMTURunner{fitPayload: low - pathMTUOverhead(pathMTUV4)}
	prober := newPathMTUProber(pathMTUPlatformLinux, runner)
	prober.overallTimeout = 300 * time.Millisecond
	prober.probeTimeout = 20 * time.Millisecond
	start := time.Now()
	mtu, err := prober.ProbeMTU(context.Background(), "198.51.100.8", low, high)
	elapsed := time.Since(start)
	if err != nil || mtu != low {
		t.Fatalf("ProbeMTU = %d, %v", mtu, err)
	}
	if elapsed >= prober.overallTimeout {
		t.Fatalf("probe consumed final recheck window: elapsed=%v budget=%v", elapsed, prober.overallTimeout)
	}
	lowProbes, blockedProbes := 0, 0
	for _, spec := range runner.specs {
		payload, parseErr := payloadFromSpec(spec)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if payload == runner.fitPayload {
			lowProbes++
		} else {
			blockedProbes++
		}
	}
	if lowProbes != pathMTUProbeSamples+pathMTUFinalSamples {
		t.Fatalf("low probes = %d, want initial plus final quorum", lowProbes)
	}
	if blockedProbes == 0 || len(runner.specs) > pathMTUMaxCommands {
		t.Fatalf("blocked probes=%d total=%d", blockedProbes, len(runner.specs))
	}
}

func TestPathMTUProductionStyleIndeterminateStillFindsSafeLowerBound(t *testing.T) {
	const low, high, threshold = 1200, 1500, 1380
	overhead := pathMTUOverhead(pathMTUV4)
	runner := &fakePathMTURunner{resultFunc: func(payload, _ int) pathMTUProbeResult {
		if payload+overhead > threshold {
			return pathMTUIndeterminate
		}
		return pathMTUFit
	}}
	prober := newPathMTUProber(pathMTUPlatformLinux, runner)
	want := highestCandidateAtOrBelow(low, high, threshold)
	if mtu, err := prober.ProbeMTU(context.Background(), "198.51.100.8", low, high); err != nil || mtu != want || mtu > threshold {
		t.Fatalf("ProbeMTU = %d, %v; want %d", mtu, err, want)
	}
}

func TestPathMTUNoQuorumOrFinalContradictionReturnsUnknown(t *testing.T) {
	tests := []struct {
		name string
		fn   func(payload, sample int) pathMTUProbeResult
	}{
		{"all indeterminate", func(_, _ int) pathMTUProbeResult { return pathMTUIndeterminate }},
		{"fit too-large contradiction", func(_ int, sample int) pathMTUProbeResult {
			return []pathMTUProbeResult{pathMTUFit, pathMTUExplicitTooLarge, pathMTUIndeterminate}[(sample-1)%3]
		}},
		{"final recheck contradiction", func(_ int, sample int) pathMTUProbeResult {
			if sample <= 3 {
				return pathMTUFit
			}
			return pathMTUExplicitTooLarge
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakePathMTURunner{resultFunc: test.fn}
			prober := newPathMTUProber(pathMTUPlatformLinux, runner)
			mtu, err := prober.ProbeMTU(context.Background(), "198.51.100.8", 1200, 1500)
			var typed *PathMTUError
			if mtu != 0 || !errors.As(err, &typed) || typed.Kind != ErrorUnavailable {
				t.Fatalf("ProbeMTU = %d, %v", mtu, err)
			}
		})
	}
}

func TestPathMTURunnerErrorsAreRedacted(t *testing.T) {
	secret := "network is unreachable: secret detail"
	runner := &fakePathMTURunner{err: errors.New(secret)}
	prober := newPathMTUProber(pathMTUPlatformLinux, runner)
	_, err := prober.ProbeMTU(context.Background(), "198.51.100.8", 1200, 1500)
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("runner detail leaked: %v", err)
	}
}

func TestPathMTUHostnameResolvesOnceAndPinsCanonicalIP(t *testing.T) {
	resolver := &fakePathMTUResolver{addrs: []netip.Addr{
		netip.MustParseAddr("2001:db8::9"),
		netip.MustParseAddr("198.51.100.9"),
		netip.MustParseAddr("198.51.100.8"),
	}}
	runner := &fakePathMTURunner{}
	prober := newPathMTUProberWithResolver(pathMTUPlatformLinux, runner, resolver)
	got, err := prober.ProbeMTU(context.Background(), "probe.example.", 1200, 1500)
	if err != nil || got != 1500 {
		t.Fatalf("ProbeMTU = %d, %v", got, err)
	}
	if resolver.calls != 1 || resolver.network != "ip" || resolver.host != "probe.example." {
		t.Fatalf("resolver calls=%d network=%q host=%q", resolver.calls, resolver.network, resolver.host)
	}
	for _, spec := range runner.specs {
		if got := spec.args[len(spec.args)-1]; got != "198.51.100.8" {
			t.Fatalf("probe target = %q, want pinned canonical IP", got)
		}
	}
}

func TestPathMTURejectsInjectionLegacyNumericAndInvalidBoundsBeforeIO(t *testing.T) {
	hostile := []string{
		"-c1", "--help", "example.com;id", "example.com\n--help", "[2001:db8::1]",
		"example..com", "éxample.com", " example.com", "127.1", "2130706433",
		"0177.0.0.1", "0x7f.0.0.1",
	}
	for _, dst := range hostile {
		t.Run(dst, func(t *testing.T) {
			runner := &fakePathMTURunner{}
			resolver := &fakePathMTUResolver{addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
			prober := newPathMTUProberWithResolver(pathMTUPlatformLinux, runner, resolver)
			if mtu, err := prober.ProbeMTU(context.Background(), dst, 1200, 1500); err == nil || mtu != 0 {
				t.Fatalf("ProbeMTU(%q) = %d, %v", dst, mtu, err)
			}
			if len(runner.specs) != 0 || resolver.calls != 0 {
				t.Fatalf("hostile destination reached IO: specs=%v calls=%d", runner.specs, resolver.calls)
			}
		})
	}
	for _, bounds := range [][2]int{{0, 1500}, {1200, 1199}, {1200, 70000}, {1000, 1000 + pathMTUMaxRange + 1}} {
		runner := &fakePathMTURunner{}
		prober := newPathMTUProber(pathMTUPlatformLinux, runner)
		if _, err := prober.ProbeMTU(context.Background(), "192.0.2.1", bounds[0], bounds[1]); err == nil {
			t.Fatalf("invalid bounds accepted: %v", bounds)
		}
		if len(runner.specs) != 0 {
			t.Fatalf("invalid bounds reached runner: %+v", runner.specs)
		}
	}
}

func TestExecPathMTURunnerTreatsNonzeroAsIndeterminate(t *testing.T) {
	if len(os.Args) != 0 && os.Args[len(os.Args)-1] == "path-mtu-exit-helper" {
		os.Exit(7)
	}
	result, err := (execPathMTURunner{}).probe(context.Background(), commandSpec{
		path: os.Args[0],
		args: []string{"-test.run=^TestExecPathMTURunnerTreatsNonzeroAsIndeterminate$", "--", "path-mtu-exit-helper"},
	})
	if err != nil || result != pathMTUIndeterminate {
		t.Fatalf("probe = %v, %v", result, err)
	}
}

func TestPathMTUFixedPlatformCommands(t *testing.T) {
	tests := []struct {
		name     string
		platform pathMTUPlatform
		family   pathMTUFamily
		dst      string
		path     string
		args     []string
	}{
		{"linux IPv4", pathMTUPlatformLinux, pathMTUV4, "192.0.2.1", "/usr/bin/ping", []string{"-4", "-n", "-c", "1", "-W", "1", "-M", "do", "-s", "1372", "192.0.2.1"}},
		{"linux IPv6", pathMTUPlatformLinux, pathMTUV6, "2001:db8::1", "/usr/bin/ping", []string{"-6", "-n", "-c", "1", "-W", "1", "-M", "do", "-s", "1352", "2001:db8::1"}},
		{"macOS IPv4", pathMTUPlatformDarwin, pathMTUV4, "192.0.2.1", "/sbin/ping", []string{"-n", "-c", "1", "-W", "1000", "-D", "-s", "1372", "192.0.2.1"}},
		{"macOS IPv6", pathMTUPlatformDarwin, pathMTUV6, "2001:db8::1", "/sbin/ping6", []string{"-n", "-c", "1", "-D", "-s", "1352", "2001:db8::1"}},
		{"Windows IPv4", pathMTUPlatformWindows, pathMTUV4, "192.0.2.1", `C:\Windows\System32\ping.exe`, []string{"-4", "-n", "1", "-w", "1000", "-f", "-l", "1372", "192.0.2.1"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec, err := pathMTUCommand(test.platform, test.family, 1400-pathMTUOverhead(test.family), test.dst)
			if err != nil {
				t.Fatal(err)
			}
			if spec.path != test.path || !equalStrings(spec.args, test.args) {
				t.Fatalf("command = %+v, want %s %#v", spec, test.path, test.args)
			}
		})
	}
}

func TestPathMTUCancellationAndResolverDeadlineAreTyped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &fakePathMTURunner{}
	prober := newPathMTUProber(pathMTUPlatformLinux, runner)
	_, err := prober.ProbeMTU(ctx, "192.0.2.1", 1200, 1500)
	var typed *PathMTUError
	if !errors.As(err, &typed) || typed.Kind != ErrorCanceled || len(runner.specs) != 0 {
		t.Fatalf("canceled probe = %v, specs=%v", err, runner.specs)
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	resolver := &fakePathMTUResolver{block: true}
	prober = newPathMTUProberWithResolver(pathMTUPlatformLinux, runner, resolver)
	_, err = prober.ProbeMTU(ctx, "probe.example", 1200, 1500)
	if !errors.As(err, &typed) || typed.Kind != ErrorTimeout || len(runner.specs) != 0 {
		t.Fatalf("resolver deadline = %v, specs=%v", err, runner.specs)
	}
}

func TestPathMTUWindowsIPv6FailsClosedBeforeRun(t *testing.T) {
	runner := &fakePathMTURunner{}
	prober := newPathMTUProber(pathMTUPlatformWindows, runner)
	if _, err := prober.ProbeMTU(context.Background(), "2001:db8::1", 1280, 1500); err == nil {
		t.Fatal("Windows IPv6 probe without no-fragment support succeeded")
	}
	if len(runner.specs) != 0 {
		t.Fatalf("unsupported Windows IPv6 reached runner: %+v", runner.specs)
	}
}

func TestPathMTULimitedBufferBoundsOutput(t *testing.T) {
	var buffer pathMTULimitedBuffer
	data := make([]byte, pathMTUMaxOutput+1)
	written, err := buffer.Write(data)
	if err != nil || written != len(data) || !buffer.overflow {
		t.Fatalf("Write = %d, %v; overflow=%v", written, err, buffer.overflow)
	}
}

func containsAdjacent(items []string, first, second string) bool {
	for index := 0; index+1 < len(items); index++ {
		if items[index] == first && items[index+1] == second {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func highestCandidateAtOrBelow(low, high, threshold int) int {
	best := -1
	for _, candidate := range pathMTUCandidates(low, high) {
		if candidate <= threshold {
			best = candidate
		}
	}
	return best
}

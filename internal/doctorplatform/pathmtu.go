package doctorplatform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/shan25519/ratelmesh/internal/diagnose"
)

const (
	pathMTUOverallTimeout = 15 * time.Second
	pathMTUProbeTimeout   = 1200 * time.Millisecond
	pathMTUMaxOutput      = 8 << 10
	pathMTUMaxCommands    = 40
	pathMTUMaxRange       = 8192
	pathMTUMaxValue       = 65535
	pathMTUMaxCandidates  = 12
	pathMTUProbeSamples   = 3
	pathMTUFinalSamples   = 3
)

// PathMTUError is a stable, output-free active-probe failure.
type PathMTUError struct {
	Kind ErrorKind
}

func (e *PathMTUError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("doctor platform path MTU probe: %s", e.Kind)
}

type pathMTUFamily uint8

const (
	pathMTUV4 pathMTUFamily = 4
	pathMTUV6 pathMTUFamily = 6
)

type pathMTUPlatform uint8

const (
	pathMTUPlatformUnsupported pathMTUPlatform = iota
	pathMTUPlatformLinux
	pathMTUPlatformDarwin
	pathMTUPlatformWindows
)

type pathMTUProbeResult uint8

const (
	pathMTUIndeterminate pathMTUProbeResult = iota
	pathMTUFit
	pathMTUExplicitTooLarge
)

type pathMTURunner interface {
	probe(context.Context, commandSpec) (pathMTUProbeResult, error)
}

type pathMTUResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// PathMTUProber performs bounded, read-only ICMP path-MTU discovery.
type PathMTUProber struct {
	platform       pathMTUPlatform
	runner         pathMTURunner
	resolver       pathMTUResolver
	overallTimeout time.Duration
	probeTimeout   time.Duration
}

var _ diagnose.PathMTUProber = (*PathMTUProber)(nil)

// NewPathMTUProber returns the production active prober for the current OS.
// Unsupported platforms return a prober which fails closed when called.
func NewPathMTUProber() diagnose.PathMTUProber {
	return &PathMTUProber{
		platform:       runtimePathMTUPlatform(runtime.GOOS),
		runner:         execPathMTURunner{},
		resolver:       net.DefaultResolver,
		overallTimeout: pathMTUOverallTimeout,
		probeTimeout:   pathMTUProbeTimeout,
	}
}

func newPathMTUProber(platform pathMTUPlatform, runner pathMTURunner) *PathMTUProber {
	return &PathMTUProber{
		platform: platform, runner: runner, resolver: net.DefaultResolver,
		overallTimeout: pathMTUOverallTimeout, probeTimeout: pathMTUProbeTimeout,
	}
}

func newPathMTUProberWithResolver(platform pathMTUPlatform, runner pathMTURunner, resolver pathMTUResolver) *PathMTUProber {
	return &PathMTUProber{
		platform: platform, runner: runner, resolver: resolver,
		overallTimeout: pathMTUOverallTimeout, probeTimeout: pathMTUProbeTimeout,
	}
}

// ProbeMTU returns a conservative, verified-usable MTU, not an exact PMTU.
// Production ping CLIs do not expose a portable, locale-independent signal
// that distinguishes packet-too-big from loss or filtering, so a nonzero exit
// is indeterminate and never becomes an inferred upper bound. A bounded grid
// is scanned independently and the largest candidate with a 2-of-3 success
// quorum is rechecked before return. Hostnames are resolved once and every
// probe is pinned to the lowest canonical address.
func (p *PathMTUProber) ProbeMTU(ctx context.Context, dst string, low, high int) (int, error) {
	if ctx == nil || p == nil || p.runner == nil || p.resolver == nil ||
		p.overallTimeout <= 0 || p.probeTimeout <= 0 {
		return 0, &PathMTUError{Kind: ErrorInvalid}
	}
	addr, hostname, err := parsePathMTUDestination(dst)
	if err != nil {
		return 0, &PathMTUError{Kind: ErrorInvalid}
	}
	if low <= 0 || high < low || high > pathMTUMaxValue || high-low > pathMTUMaxRange {
		return 0, &PathMTUError{Kind: ErrorInvalid}
	}
	if p.platform == pathMTUPlatformUnsupported {
		return 0, &PathMTUError{Kind: ErrorUnavailable}
	}

	ctx, cancel := context.WithTimeout(ctx, p.overallTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return 0, pathMTUContextError(err)
	}
	if hostname != "" {
		addr, err = p.resolveDestination(ctx, hostname)
		if err != nil {
			return 0, err
		}
	}
	family := pathMTUV6
	if addr.Is4() {
		family = pathMTUV4
	}
	overhead := pathMTUOverhead(family)
	if low <= overhead {
		return 0, &PathMTUError{Kind: ErrorInvalid}
	}
	if p.platform == pathMTUPlatformWindows && family == pathMTUV6 {
		return 0, &PathMTUError{Kind: ErrorUnavailable}
	}
	target := addr.String()
	commands := 0
	classify := func(mtu, samples int) (pathMTUProbeResult, error) {
		fit, tooLarge := 0, 0
		for sample := 0; sample < samples; sample++ {
			if err := ctx.Err(); err != nil {
				return pathMTUIndeterminate, pathMTUContextError(err)
			}
			if commands >= pathMTUMaxCommands {
				return pathMTUIndeterminate, &PathMTUError{Kind: ErrorOversized}
			}
			spec, specErr := pathMTUCommand(p.platform, family, mtu-overhead, target)
			if specErr != nil {
				return pathMTUIndeterminate, &PathMTUError{Kind: ErrorUnavailable}
			}
			commands++
			probeCtx, probeCancel := context.WithTimeout(ctx, p.probeTimeout)
			result, probeErr := p.runner.probe(probeCtx, spec)
			contextErr := probeCtx.Err()
			probeCancel()
			if overallErr := ctx.Err(); overallErr != nil {
				return pathMTUIndeterminate, pathMTUContextError(overallErr)
			}
			if contextErr != nil {
				// A per-probe timeout is observationally the same as loss.
				// It cannot establish an upper bound and does not prevent
				// independent candidates from being tested.
				continue
			}
			if probeErr != nil {
				var typed *PathMTUError
				if errors.As(probeErr, &typed) {
					return pathMTUIndeterminate, typed
				}
				return pathMTUIndeterminate, &PathMTUError{Kind: ErrorUnavailable}
			}
			switch result {
			case pathMTUFit:
				fit++
			case pathMTUExplicitTooLarge:
				tooLarge++
			}
		}
		quorum := samples/2 + 1
		if fit >= quorum {
			return pathMTUFit, nil
		}
		if tooLarge >= quorum {
			return pathMTUExplicitTooLarge, nil
		}
		return pathMTUIndeterminate, nil
	}

	best := -1
	perProbeBudget := p.probeTimeout + pathMTUSchedulingSlack(p.probeTimeout)
	finalReserve := time.Duration(pathMTUFinalSamples) * perProbeBudget
	candidateWorstCase := time.Duration(pathMTUProbeSamples) * perProbeBudget
	for _, candidate := range pathMTUCandidates(low, high) {
		// Never spend the window needed to independently recheck a candidate
		// already known to fit. Before the first fit, preserve the same window
		// because the candidate being started may become that first fit.
		if !pathMTUHasBudget(ctx, candidateWorstCase+finalReserve) {
			break
		}
		result, classifyErr := classify(candidate, pathMTUProbeSamples)
		if classifyErr != nil {
			return 0, classifyErr
		}
		if result == pathMTUFit {
			best = candidate
		}
	}
	if best < 0 {
		return 0, &PathMTUError{Kind: ErrorUnavailable}
	}
	finalResult, err := classify(best, pathMTUFinalSamples)
	if err != nil {
		return 0, err
	}
	if finalResult != pathMTUFit {
		return 0, &PathMTUError{Kind: ErrorUnavailable}
	}
	return best, nil
}

func pathMTUHasBudget(ctx context.Context, needed time.Duration) bool {
	deadline, ok := ctx.Deadline()
	return !ok || time.Until(deadline) >= needed
}

func pathMTUSchedulingSlack(probeTimeout time.Duration) time.Duration {
	slack := probeTimeout / 10
	const maximumSlack = 250 * time.Millisecond
	if slack > maximumSlack {
		return maximumSlack
	}
	return slack
}

func pathMTUCandidates(low, high int) []int {
	if low == high {
		return []int{low}
	}
	count := pathMTUMaxCandidates
	if high-low+1 < count {
		count = high - low + 1
	}
	candidates := make([]int, 0, count)
	for index := 0; index < count; index++ {
		candidate := low + (high-low)*index/(count-1)
		if len(candidates) == 0 || candidates[len(candidates)-1] != candidate {
			candidates = append(candidates, candidate)
		}
	}
	const ipv6MinimumMTU = 1280
	if ipv6MinimumMTU > low && ipv6MinimumMTU < high && !slices.Contains(candidates, ipv6MinimumMTU) {
		if len(candidates) < pathMTUMaxCandidates {
			candidates = append(candidates, ipv6MinimumMTU)
		} else {
			replace := 1
			bestDistance := pathMTUAbs(candidates[replace] - ipv6MinimumMTU)
			for index := 2; index < len(candidates)-1; index++ {
				if distance := pathMTUAbs(candidates[index] - ipv6MinimumMTU); distance < bestDistance {
					replace, bestDistance = index, distance
				}
			}
			candidates[replace] = ipv6MinimumMTU
		}
		slices.Sort(candidates)
	}
	return candidates
}

func pathMTUAbs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func (p *PathMTUProber) resolveDestination(ctx context.Context, hostname string) (netip.Addr, error) {
	addrs, err := p.resolver.LookupNetIP(ctx, "ip", hostname)
	if contextErr := ctx.Err(); contextErr != nil {
		return netip.Addr{}, pathMTUContextError(contextErr)
	}
	if err != nil {
		return netip.Addr{}, &PathMTUError{Kind: ErrorUnavailable}
	}
	canonical := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if !addr.IsValid() || addr.IsUnspecified() {
			continue
		}
		addr = addr.Unmap()
		if p.platform == pathMTUPlatformWindows && addr.Is6() {
			continue
		}
		canonical = append(canonical, addr)
	}
	if len(canonical) == 0 {
		return netip.Addr{}, &PathMTUError{Kind: ErrorUnavailable}
	}
	slices.SortFunc(canonical, netip.Addr.Compare)
	return canonical[0], nil
}

func parsePathMTUDestination(dst string) (netip.Addr, string, error) {
	if dst == "" || dst != strings.TrimSpace(dst) {
		return netip.Addr{}, "", errMalformed
	}
	if addr, err := netip.ParseAddr(dst); err == nil {
		return addr.Unmap(), "", nil
	}
	if !validProbeHostname(dst) || legacyNumericAddress(dst) {
		return netip.Addr{}, "", errMalformed
	}
	return netip.Addr{}, dst, nil
}

func legacyNumericAddress(host string) bool {
	host = strings.TrimSuffix(host, ".")
	allDecimal := true
	for _, char := range host {
		if (char < '0' || char > '9') && char != '.' {
			allDecimal = false
			break
		}
	}
	if allDecimal {
		return true
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		base := 10
		digits := label
		if strings.HasPrefix(label, "0x") || strings.HasPrefix(label, "0X") {
			base, digits = 16, label[2:]
		} else if len(label) > 1 && label[0] == '0' {
			base = 8
		}
		if digits == "" {
			return false
		}
		for _, char := range digits {
			valid := char >= '0' && char <= '9'
			if base == 8 {
				valid = char >= '0' && char <= '7'
			} else if base == 16 {
				valid = valid || char >= 'a' && char <= 'f' || char >= 'A' && char <= 'F'
			}
			if !valid {
				return false
			}
		}
	}
	return true
}

func pathMTUDestinationFamily(dst string) (pathMTUFamily, error) {
	addr, hostname, err := parsePathMTUDestination(dst)
	if err != nil {
		return 0, err
	}
	if hostname != "" || addr.Is4() {
		return pathMTUV4, nil
	}
	return pathMTUV6, nil
}

func runtimePathMTUPlatform(goos string) pathMTUPlatform {
	switch goos {
	case "linux":
		return pathMTUPlatformLinux
	case "darwin":
		return pathMTUPlatformDarwin
	case "windows":
		return pathMTUPlatformWindows
	default:
		return pathMTUPlatformUnsupported
	}
}

func validProbeHostname(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > maxDomainSize || strings.HasPrefix(host, "-") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !((char >= 'a' && char <= 'z') ||
				(char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') ||
				char == '-') {
				return false
			}
		}
	}
	return true
}

func pathMTUOverhead(family pathMTUFamily) int {
	if family == pathMTUV6 {
		return 48 // 40-byte IPv6 header + 8-byte ICMPv6 header.
	}
	return 28 // 20-byte IPv4 header + 8-byte ICMP header.
}

func pathMTUCommand(platform pathMTUPlatform, family pathMTUFamily, payload int, dst string) (commandSpec, error) {
	size := strconv.Itoa(payload)
	switch platform {
	case pathMTUPlatformLinux:
		familyArg := "-4"
		if family == pathMTUV6 {
			familyArg = "-6"
		}
		return commandSpec{
			path: "/usr/bin/ping",
			args: []string{familyArg, "-n", "-c", "1", "-W", "1", "-M", "do", "-s", size, dst},
		}, nil
	case pathMTUPlatformDarwin:
		if family == pathMTUV6 {
			return commandSpec{
				path: "/sbin/ping6",
				args: []string{"-n", "-c", "1", "-D", "-s", size, dst},
			}, nil
		}
		return commandSpec{
			path: "/sbin/ping",
			args: []string{"-n", "-c", "1", "-W", "1000", "-D", "-s", size, dst},
		}, nil
	case pathMTUPlatformWindows:
		if family == pathMTUV6 {
			// Windows ping.exe exposes -f only for IPv4. Its IPv6 form cannot
			// guarantee source-side no-fragment semantics, so fail closed
			// instead of reporting a potentially fragmented false MTU.
			return commandSpec{}, errMalformed
		}
		return commandSpec{
			path: `C:\Windows\System32\ping.exe`,
			args: []string{"-4", "-n", "1", "-w", "1000", "-f", "-l", size, dst},
		}, nil
	default:
		return commandSpec{}, errMalformed
	}
}

type execPathMTURunner struct{}

func (execPathMTURunner) probe(ctx context.Context, spec commandSpec) (pathMTUProbeResult, error) {
	var stdout pathMTULimitedBuffer
	var stderr pathMTULimitedBuffer
	command := exec.CommandContext(ctx, spec.path, spec.args...)
	command.Stdin = nil
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if ctx.Err() != nil {
		return pathMTUIndeterminate, pathMTUContextError(ctx.Err())
	}
	if stdout.overflow || stderr.overflow {
		return pathMTUIndeterminate, &PathMTUError{Kind: ErrorOversized}
	}
	if err == nil {
		return pathMTUFit, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// ping exit status cannot portably distinguish packet-too-big from
		// loss, filtering, or no route. Never use it to shrink the MTU.
		return pathMTUIndeterminate, nil
	}
	return pathMTUIndeterminate, &PathMTUError{Kind: ErrorUnavailable}
}

type pathMTULimitedBuffer struct {
	buffer   bytes.Buffer
	overflow bool
}

func (b *pathMTULimitedBuffer) Write(data []byte) (int, error) {
	original := len(data)
	remaining := pathMTUMaxOutput + 1 - b.buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = b.buffer.Write(data)
	}
	if b.buffer.Len() > pathMTUMaxOutput {
		b.overflow = true
	}
	return original, nil
}

func pathMTUContextError(err error) error {
	if errors.Is(err, context.Canceled) {
		return &PathMTUError{Kind: ErrorCanceled}
	}
	return &PathMTUError{Kind: ErrorTimeout}
}

package remoteaccess

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"time"
)

var (
	ErrTooManyCandidates = errors.New("too many candidates")
)

const (
	MaxCandidates          = 10
	DefaultDetectorTimeout = 2 * time.Second
	MaxDetectorTimeout     = 5 * time.Second
)

type DetectionFailureCode string

const (
	FailureInvalidCandidate DetectionFailureCode = "invalid_candidate"
	FailureUnreachable      DetectionFailureCode = "unreachable"
	FailureTimeout          DetectionFailureCode = "timeout"
)

// Candidate represents an explicitly allowed local service to probe.
type Candidate struct {
	Kind  ServiceKind `json:"kind"`
	Port  uint16      `json:"port"`
	Label string      `json:"label"`
}

type DetectionFailure struct {
	Candidate Candidate            `json:"candidate"`
	Code      DetectionFailureCode `json:"code"`
}

type DetectionResult struct {
	Services []ServiceAdvertisement `json:"services"`
	Failures []DetectionFailure     `json:"failures"`
}

// Detector probes an explicit allowlist of local services.
// Note: Detector proves ONLY a reachable explicitly allowlisted TCP listener,
// not application-protocol identity. Integrators/UI must not describe it as
// cryptographically verified protocol identity.
type Detector struct {
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	Timeout     time.Duration
}

// NewDetector creates a Detector with the default net.Dialer and timeout.
func NewDetector() *Detector {
	return &Detector{
		DialContext: (&net.Dialer{}).DialContext,
		Timeout:     DefaultDetectorTimeout,
	}
}

// DefaultCandidates returns the standard platform ports.
func DefaultCandidates(platform Platform) []Candidate {
	switch platform {
	case PlatformMacOS:
		return []Candidate{
			{Kind: KindSSH, Port: 22, Label: "SSH"},
			{Kind: KindVNC, Port: 5900, Label: "VNC"},
		}
	case PlatformWindows:
		return []Candidate{
			{Kind: KindSSH, Port: 22, Label: "SSH"},
			{Kind: KindRDP, Port: 3389, Label: "RDP"},
		}
	case PlatformLinux:
		return []Candidate{
			{Kind: KindSSH, Port: 22, Label: "SSH"},
			{Kind: KindVNC, Port: 5900, Label: "VNC"},
		}
	default:
		return []Candidate{}
	}
}

// candKey is used for deduplicating identical services.
type candKey struct {
	Kind ServiceKind
	Port uint16
}

// Detect probes the allowlisted candidates and returns the valid, reachable ServiceAdvertisements,
// along with any stable failure codes for unreachable or invalid candidates.
//
// Callers MUST discard results when the returned error is non-nil, though
// partial-result cancellation semantics are preserved internally.
func (d *Detector) Detect(ctx context.Context, platform Platform, targetNodeID, targetMeshIP string, candidates []Candidate) (*DetectionResult, error) {
	if d == nil || d.DialContext == nil || ctx == nil {
		return nil, ErrNilPointer
	}

	if len(candidates) > MaxCandidates {
		return nil, ErrTooManyCandidates
	}

	// Validate target parameters unconditionally (even if candidates empty)
	dummyAdv := ServiceAdvertisement{
		Kind:         KindSSH,
		Port:         22,
		Platform:     platform,
		Label:        "dummy",
		TargetNodeID: targetNodeID,
		TargetMeshIP: targetMeshIP,
	}
	if platform == PlatformWindows {
		dummyAdv.Kind = KindRDP
	}
	if err := dummyAdv.Validate(); err != nil {
		return nil, err
	}

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = DefaultDetectorTimeout
	}
	if timeout > MaxDetectorTimeout {
		timeout = MaxDetectorTimeout
	}

	// Deduplicate identical candidates based on Kind+Port identity, ignoring Label.
	seen := make(map[candKey]bool)
	var deduped []Candidate
	for _, cand := range candidates {
		k := candKey{Kind: cand.Kind, Port: cand.Port}
		if !seen[k] {
			seen[k] = true
			deduped = append(deduped, cand)
		}
	}

	res := &DetectionResult{}

	for _, cand := range deduped {
		if err := ctx.Err(); err != nil {
			return res, err
		}

		adv := ServiceAdvertisement{
			Kind:         cand.Kind,
			Port:         cand.Port,
			Platform:     platform,
			Label:        cand.Label,
			TargetNodeID: targetNodeID,
			TargetMeshIP: targetMeshIP,
		}

		if err := adv.Validate(); err != nil {
			res.Failures = append(res.Failures, DetectionFailure{Candidate: cand, Code: FailureInvalidCandidate})
			continue
		}

		// Probe the exact address that peers will use. A loopback listener does
		// not prove that the service is bound to the advertised Mesh address.
		addr := net.JoinHostPort(targetMeshIP, strconv.Itoa(int(cand.Port)))

		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := d.DialContext(probeCtx, "tcp", addr)
		cancel()

		if err == nil && conn != nil {
			conn.Close()
			res.Services = append(res.Services, adv)
		} else {
			if errors.Is(err, context.DeadlineExceeded) {
				res.Failures = append(res.Failures, DetectionFailure{Candidate: cand, Code: FailureTimeout})
			} else {
				res.Failures = append(res.Failures, DetectionFailure{Candidate: cand, Code: FailureUnreachable})
			}
		}
	}

	sort.Slice(res.Services, func(i, j int) bool {
		if res.Services[i].Kind == res.Services[j].Kind {
			if res.Services[i].Port == res.Services[j].Port {
				return res.Services[i].Label < res.Services[j].Label
			}
			return res.Services[i].Port < res.Services[j].Port
		}
		return res.Services[i].Kind < res.Services[j].Kind
	})

	sort.Slice(res.Failures, func(i, j int) bool {
		if res.Failures[i].Candidate.Kind == res.Failures[j].Candidate.Kind {
			if res.Failures[i].Candidate.Port == res.Failures[j].Candidate.Port {
				return res.Failures[i].Candidate.Label < res.Failures[j].Candidate.Label
			}
			return res.Failures[i].Candidate.Port < res.Failures[j].Candidate.Port
		}
		return res.Failures[i].Candidate.Kind < res.Failures[j].Candidate.Kind
	})

	return res, nil
}

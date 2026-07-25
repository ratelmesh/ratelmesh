package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"testing"

	"github.com/shan25519/ratelmesh/internal/remoteaccess"
	"github.com/shan25519/ratelmesh/internal/types"
)

type recordingRemoteDetector struct {
	platform   remoteaccess.Platform
	nodeID     string
	meshIP     string
	candidates []remoteaccess.Candidate
	result     *remoteaccess.DetectionResult
	err        error
	calls      int
}

func (d *recordingRemoteDetector) Detect(_ context.Context, platform remoteaccess.Platform, nodeID, meshIP string, candidates []remoteaccess.Candidate) (*remoteaccess.DetectionResult, error) {
	d.calls++
	d.platform = platform
	d.nodeID = nodeID
	d.meshIP = meshIP
	d.candidates = append([]remoteaccess.Candidate(nil), candidates...)
	return d.result, d.err
}

func newRemoteAccessTestDaemon(detector RemoteServiceDetector, allowed bool) *Daemon {
	return &Daemon{
		cfg: Config{RemoteServiceDetector: detector},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAccess: remoteAccessView{
			selfAllowed: allowed,
			services:    make(map[remoteTargetKey][]remoteAuthorizedService),
		},
		lastNetmap: types.Netmap{Self: types.Node{
			RemoteAccessAllowed: allowed,
			MeshIPs:             []netip.Addr{netip.MustParseAddr("100.64.0.5")},
		}},
	}
}

func TestDetectRemoteServicesIsPolicyGatedAndClearsWhenOff(t *testing.T) {
	detector := &recordingRemoteDetector{}
	d := newRemoteAccessTestDaemon(detector, false)

	got, advertise := d.detectRemoteServices(context.Background(), "node-1", "macos")
	if !advertise || got == nil || len(got) != 0 {
		t.Fatalf("policy-off result = (%+v, %v), want explicit empty advertisement", got, advertise)
	}
	if detector.calls != 0 {
		t.Fatalf("policy-off detection calls = %d, want 0", detector.calls)
	}
}

func TestDetectRemoteServicesPublishesOnlyDetectorResult(t *testing.T) {
	service := remoteaccess.ServiceAdvertisement{
		Kind:         remoteaccess.KindSSH,
		Port:         22,
		Platform:     remoteaccess.PlatformMacOS,
		Label:        "SSH",
		TargetNodeID: "node-1",
		TargetMeshIP: "100.64.0.5",
	}
	detector := &recordingRemoteDetector{
		result: &remoteaccess.DetectionResult{Services: []remoteaccess.ServiceAdvertisement{service}},
	}
	d := newRemoteAccessTestDaemon(detector, true)
	candidates := []remoteaccess.Candidate{{Kind: remoteaccess.KindSSH, Port: 2222, Label: "Admin SSH"}}
	d.cfg.RemoteAccessCandidates = candidates

	got, advertise := d.detectRemoteServices(context.Background(), "node-1", "macos")
	if !advertise || !reflect.DeepEqual(got, []remoteaccess.ServiceAdvertisement{service}) {
		t.Fatalf("result = (%+v, %v), want detector service", got, advertise)
	}
	if detector.calls != 1 || detector.platform != remoteaccess.PlatformMacOS || detector.nodeID != "node-1" || detector.meshIP != "100.64.0.5" {
		t.Fatalf("detector binding = calls %d platform %q node %q ip %q", detector.calls, detector.platform, detector.nodeID, detector.meshIP)
	}
	if !reflect.DeepEqual(detector.candidates, candidates) {
		t.Fatalf("candidates = %+v, want %+v", detector.candidates, candidates)
	}
}

func TestDetectRemoteServicesPreservesObservationOnTransientFailure(t *testing.T) {
	detector := &recordingRemoteDetector{err: errors.New("temporary detector failure")}
	d := newRemoteAccessTestDaemon(detector, true)

	got, advertise := d.detectRemoteServices(context.Background(), "node-1", "linux")
	if advertise || got != nil {
		t.Fatalf("transient failure result = (%+v, %v), want nil preserve signal", got, advertise)
	}
}

func TestDetectRemoteServicesClearsUnsupportedPlatform(t *testing.T) {
	detector := &recordingRemoteDetector{}
	d := newRemoteAccessTestDaemon(detector, true)

	got, advertise := d.detectRemoteServices(context.Background(), "node-1", "android")
	if !advertise || got == nil || len(got) != 0 {
		t.Fatalf("unsupported-platform result = (%+v, %v), want explicit empty", got, advertise)
	}
	if detector.calls != 0 {
		t.Fatalf("unsupported-platform detection calls = %d, want 0", detector.calls)
	}
}

func TestDetectRemoteServicesPreservesWithoutMeshIP(t *testing.T) {
	detector := &recordingRemoteDetector{}
	d := newRemoteAccessTestDaemon(detector, true)
	d.lastNetmap.Self.MeshIPs = nil

	got, advertise := d.detectRemoteServices(context.Background(), "node-1", "windows")
	if advertise || got != nil {
		t.Fatalf("missing-IP result = (%+v, %v), want nil preserve signal", got, advertise)
	}
	if detector.calls != 0 {
		t.Fatalf("missing-IP detection calls = %d, want 0", detector.calls)
	}
}

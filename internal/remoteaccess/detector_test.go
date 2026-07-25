package remoteaccess

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type mockConn struct{ net.Conn }

func (m *mockConn) Close() error { return nil }

func TestDefaultCandidates(t *testing.T) {
	mac := DefaultCandidates(PlatformMacOS)
	if len(mac) != 2 || mac[0].Kind != KindSSH || mac[1].Kind != KindVNC {
		t.Errorf("unexpected macos defaults")
	}
	win := DefaultCandidates(PlatformWindows)
	if len(win) != 2 || win[1].Kind != KindRDP {
		t.Errorf("unexpected windows defaults")
	}
	lin := DefaultCandidates(PlatformLinux)
	if len(lin) != 2 || lin[1].Kind != KindVNC {
		t.Errorf("unexpected linux defaults")
	}
}

func TestDetector_Detect(t *testing.T) {
	d := &Detector{
		Timeout: 50 * time.Millisecond,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				if addr == "100.64.0.1:22" {
					return &mockConn{}, nil
				}
				if addr == "100.64.0.1:5900" {
					return &mockConn{}, nil
				}
				if addr == "100.64.0.1:9999" {
					// Simulate a timeout within the simulated dialer
					time.Sleep(100 * time.Millisecond)
					return nil, context.DeadlineExceeded
				}
				return nil, errors.New("connection refused")
			}
		},
	}

	ctx := context.Background()

	// 1. Nil checks
	var nilDetector *Detector
	_, err := nilDetector.Detect(ctx, PlatformMacOS, "n1", "100.64.0.1", nil)
	if err != ErrNilPointer {
		t.Errorf("expected ErrNilPointer, got %v", err)
	}

	badDetector := &Detector{DialContext: nil}
	_, err = badDetector.Detect(ctx, PlatformMacOS, "n1", "100.64.0.1", nil)
	if err != ErrNilPointer {
		t.Errorf("expected ErrNilPointer, got %v", err)
	}

	_, err = d.Detect(nil, PlatformMacOS, "n1", "100.64.0.1", nil)
	if err != ErrNilPointer {
		t.Errorf("expected ErrNilPointer for nil context, got %v", err)
	}

	// 2. Validate bounds even on empty candidates
	_, err = d.Detect(ctx, PlatformMacOS, "n1", "invalid-ip", []Candidate{})
	if err != ErrInvalidMeshIP {
		t.Errorf("expected ErrInvalidMeshIP on empty candidates, got %v", err)
	}

	// 3. Complex detection scenario
	candidates := []Candidate{
		{Kind: KindSSH, Port: 22, Label: "SSH"},
		{Kind: KindSSH, Port: 22, Label: "Alt SSH"}, // duplicate, should be deduped (first kept)
		{Kind: KindVNC, Port: 5900, Label: "VNC"},
		{Kind: KindRDP, Port: 3389, Label: "RDP"},      // invalid for macos
		{Kind: KindSSH, Port: 2222, Label: "Alt SSH"},  // unreachable
		{Kind: KindSSH, Port: 9999, Label: "Slow SSH"}, // timeout
	}

	res, err := d.Detect(ctx, PlatformMacOS, "n1", "100.64.0.1", candidates)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if len(res.Services) != 2 {
		t.Fatalf("expected 2 healthy services, got %d", len(res.Services))
	}
	if res.Services[0].Kind != KindSSH || res.Services[0].Port != 22 {
		t.Errorf("expected first service SSH:22, got %v", res.Services[0])
	}
	if res.Services[1].Kind != KindVNC || res.Services[1].Port != 5900 {
		t.Errorf("expected second service VNC:5900, got %v", res.Services[1])
	}

	if len(res.Failures) != 3 {
		t.Fatalf("expected 3 failures (deduped), got %d", len(res.Failures))
	}

	// Check failure codes
	failureCodes := make(map[uint16]DetectionFailureCode)
	for _, f := range res.Failures {
		failureCodes[f.Candidate.Port] = f.Code
	}
	if failureCodes[3389] != FailureInvalidCandidate {
		t.Errorf("expected 3389 to be invalid_candidate, got %v", failureCodes[3389])
	}
	if failureCodes[2222] != FailureUnreachable {
		t.Errorf("expected 2222 to be unreachable, got %v", failureCodes[2222])
	}
	if failureCodes[9999] != FailureTimeout {
		t.Errorf("expected 9999 to be timeout, got %v", failureCodes[9999])
	}

	// 4. Parent cancellation
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	resCancel, errCancel := d.Detect(cancelCtx, PlatformMacOS, "n1", "100.64.0.1", candidates)
	if errCancel != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", errCancel)
	}
	if resCancel == nil || len(resCancel.Services) != 0 || len(resCancel.Failures) != 0 {
		t.Errorf("expected empty partial result on pre-cancelled context, got %v", resCancel)
	}
}

func TestDetectorProbesAdvertisedMeshAddressOnly(t *testing.T) {
	var got []string
	d := &Detector{
		DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			got = append(got, addr)
			if addr == "[fd00::7]:6022" {
				return &mockConn{}, nil
			}
			return nil, errors.New("unexpected address")
		},
	}
	result, err := d.Detect(
		context.Background(),
		PlatformLinux,
		"node-v6",
		"fd00::7",
		[]Candidate{{Kind: KindSSH, Port: 6022, Label: "SSH"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Services) != 1 || len(got) != 1 || got[0] != "[fd00::7]:6022" {
		t.Fatalf("probed %v, result %#v", got, result)
	}
}

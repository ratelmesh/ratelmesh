package daemon

import (
	"context"
	"log/slog"

	"github.com/shan25519/ratelmesh/internal/remoteaccess"
)

// RemoteServiceDetector is the target-local detection seam. Production uses
// remoteaccess.Detector; tests and native platform adapters can inject an
// equivalent bounded implementation without giving the Coordinator a scanner.
type RemoteServiceDetector interface {
	Detect(context.Context, remoteaccess.Platform, string, string, []remoteaccess.Candidate) (*remoteaccess.DetectionResult, error)
}

func (d *Daemon) detectRemoteServices(ctx context.Context, nodeID, platformName string) ([]remoteaccess.ServiceAdvertisement, bool) {
	d.mu.Lock()
	self := d.lastNetmap.Self
	remoteAllowed := d.remoteAccess.selfAllowed
	d.mu.Unlock()

	if !remoteAllowed {
		return []remoteaccess.ServiceAdvertisement{}, true
	}
	platform := remoteaccess.Platform(platformName)
	switch platform {
	case remoteaccess.PlatformMacOS, remoteaccess.PlatformWindows, remoteaccess.PlatformLinux:
	default:
		return []remoteaccess.ServiceAdvertisement{}, true
	}
	if len(self.MeshIPs) == 0 {
		return nil, false
	}

	detector := d.cfg.RemoteServiceDetector
	if detector == nil {
		detector = remoteaccess.NewDetector()
	}
	candidates := d.cfg.RemoteAccessCandidates
	if candidates == nil {
		candidates = remoteaccess.DefaultCandidates(platform)
	} else {
		candidates = append([]remoteaccess.Candidate(nil), candidates...)
	}
	result, err := detector.Detect(ctx, platform, nodeID, self.MeshIPs[0].String(), candidates)
	if err != nil {
		d.log.Warn("remote-service detection failed", "err", err)
		return nil, false
	}
	for _, failure := range result.Failures {
		d.log.Debug("remote-service listener unavailable",
			slog.String("kind", string(failure.Candidate.Kind)),
			slog.Int("port", int(failure.Candidate.Port)),
			slog.String("code", string(failure.Code)))
	}
	return append([]remoteaccess.ServiceAdvertisement(nil), result.Services...), true
}

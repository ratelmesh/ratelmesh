package daemon

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/magicsock"
	"github.com/ratelmesh/ratelmesh/internal/types"
	"github.com/ratelmesh/ratelmesh/internal/wgengine"
)

const (
	maxDiscoUpgradeProbes = 4
	discoProbeTimeout     = 750 * time.Millisecond
	discoProbeRetry       = 30 * time.Second
	discoPermitLifetime   = 10 * time.Second
)

type discoProbeFunc func(context.Context, netip.AddrPort, time.Duration) error

// discoUpgradePeer is guarded by Daemon.mu. A successful disco ping grants one
// short-lived direct trial; it never changes a WireGuard endpoint by itself.
type discoUpgradePeer struct {
	fingerprint string
	relayCycle  time.Time

	attemptID uint64
	probing   bool
	permitAt  time.Time
	nextProbe time.Time

	directTrial       bool
	baselineRx        int64
	baselineHandshake time.Time
	trialFailures     int
}

type discoProbeAttempt struct {
	key         types.Key
	fingerprint string
	relayCycle  time.Time
	attemptID   uint64
	candidates  []netip.AddrPort
}

func usableDiscoEndpoints(raw []string) []netip.AddrPort {
	candidates := probeCandidateEndpoints(raw)
	out := candidates[:0]
	for _, candidate := range candidates {
		if !candidate.Addr().IsUnspecified() {
			out = append(out, candidate)
		}
	}
	return out
}

func discoUpgradeFingerprint(p types.Node) string {
	var b strings.Builder
	for _, endpoint := range probeCandidateEndpoints(p.Endpoints) {
		b.WriteString(endpoint.String())
		b.WriteByte(0)
	}
	b.WriteByte(1)
	for _, endpoint := range usableDiscoEndpoints(p.DiscoEndpoints) {
		b.WriteString(endpoint.String())
		b.WriteByte(0)
	}
	return b.String()
}

func (d *Daemon) servingExitLocked() bool {
	return d.cfg.Role == types.RoleExit ||
		d.lastNetmap.Self.Capabilities.Exit ||
		d.lastNetmap.Self.Role == types.RoleExit
}

func (d *Daemon) discoUpgradeGateEnabledLocked(p types.Node) bool {
	return d.cfg.EnableDiscoProbe &&
		!d.cfg.ForceRelay &&
		d.bridge != nil &&
		len(usableDiscoEndpoints(p.DiscoEndpoints)) > 0
}

func (d *Daemon) discoProbePeerEligibleLocked(p types.Node) bool {
	return p.Online &&
		d.discoUpgradeGateEnabledLocked(p) &&
		!d.servingExitLocked() &&
		!peerMatches(p, d.preferredExit)
}

func (d *Daemon) discoUpgradeStateLocked(p types.Node) *discoUpgradePeer {
	if d.discoUpgrades == nil {
		d.discoUpgrades = make(map[types.Key]*discoUpgradePeer)
	}
	fingerprint := discoUpgradeFingerprint(p)
	relayCycle := d.relaySince[p.Key]
	state := d.discoUpgrades[p.Key]
	if state == nil || state.fingerprint != fingerprint || !state.relayCycle.Equal(relayCycle) {
		state = &discoUpgradePeer{
			fingerprint: fingerprint,
			relayCycle:  relayCycle,
		}
		d.discoUpgrades[p.Key] = state
	}
	return state
}

// startDueDiscoUpgradeProbes schedules bounded, out-of-band reachability work.
// All decisions and state snapshots happen under d.mu; UDP I/O happens after
// unlocking. When the cap is full, skipped peers are reconsidered on the next
// three-second relay tick.
func (d *Daemon) startDueDiscoUpgradeProbes(
	ctx context.Context,
	stats map[types.Key]wgengine.PeerStat,
	now time.Time,
) {
	if ctx.Err() != nil {
		return
	}
	d.mu.Lock()
	if !d.cfg.EnableDiscoProbe || d.cfg.ForceRelay || d.bridge == nil {
		d.mu.Unlock()
		return
	}

	present := make(map[types.Key]bool, len(d.lastNetmap.Peers))
	attempts := make([]discoProbeAttempt, 0, maxDiscoUpgradeProbes)
	for _, p := range d.lastNetmap.Peers {
		present[p.Key] = true
		if d.discoProbesInFlight >= maxDiscoUpgradeProbes {
			continue
		}
		if !d.relayed[p.Key] || !d.discoProbePeerEligibleLocked(p) {
			continue
		}
		relaySince, ok := d.relaySince[p.Key]
		if !ok || now.Sub(relaySince) <= upgradeRetry {
			continue
		}
		progress := d.rxProgress[p.Key]
		healthy := handshakeIsFresh(stats[p.Key], now, relaySince) ||
			(!progress.IsZero() && progress.After(relaySince) && now.Sub(progress) < livenessWindow)
		if !healthy {
			continue
		}

		candidates := usableDiscoEndpoints(p.DiscoEndpoints)
		if len(candidates) == 0 {
			continue
		}
		state := d.discoUpgradeStateLocked(p)
		if state.probing ||
			(!state.permitAt.IsZero() && now.Sub(state.permitAt) <= discoPermitLifetime) ||
			now.Before(state.nextProbe) {
			continue
		}
		if !state.permitAt.IsZero() {
			state.permitAt = time.Time{}
		}
		d.discoProbeSequence++
		state.attemptID = d.discoProbeSequence
		state.probing = true
		state.nextProbe = now.Add(discoProbeRetry)
		d.discoProbesInFlight++
		attempts = append(attempts, discoProbeAttempt{
			key:         p.Key,
			fingerprint: state.fingerprint,
			relayCycle:  state.relayCycle,
			attemptID:   state.attemptID,
			candidates:  append([]netip.AddrPort(nil), candidates...),
		})
	}
	for key, state := range d.discoUpgrades {
		if !present[key] && !state.probing {
			delete(d.discoUpgrades, key)
		}
	}
	probe := d.discoProbe
	if probe == nil {
		probe = magicsock.Probe
	}
	if d.discoProbeSlots == nil {
		d.discoProbeSlots = make(chan struct{}, maxDiscoUpgradeProbes)
	}
	probeSlots := d.discoProbeSlots
	d.mu.Unlock()

	for _, attempt := range attempts {
		attempt := attempt
		go func() {
			success := probeDiscoCandidates(ctx, attempt.candidates, probe, probeSlots)
			d.finishDiscoUpgradeProbe(attempt, success, time.Now())
		}()
	}
}

func probeDiscoCandidates(
	ctx context.Context,
	candidates []netip.AddrPort,
	probe discoProbeFunc,
	probeSlots chan struct{},
) bool {
	if len(candidates) == 0 || ctx.Err() != nil {
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, discoProbeTimeout)
	defer cancel()
	results := make(chan bool, len(candidates))
	for _, candidate := range candidates {
		candidate := candidate
		go func() {
			select {
			case probeSlots <- struct{}{}:
			case <-probeCtx.Done():
				results <- false
				return
			}
			err := probe(probeCtx, candidate, discoProbeTimeout)
			<-probeSlots
			results <- err == nil
		}()
	}
	success := false
	for range candidates {
		if <-results {
			success = true
			cancel()
		}
	}
	return success
}

func (d *Daemon) finishDiscoUpgradeProbe(
	attempt discoProbeAttempt,
	success bool,
	now time.Time,
) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.discoProbesInFlight > 0 {
		d.discoProbesInFlight--
	}
	state := d.discoUpgrades[attempt.key]
	if state == nil ||
		state.attemptID != attempt.attemptID ||
		state.fingerprint != attempt.fingerprint ||
		!state.relayCycle.Equal(attempt.relayCycle) {
		return
	}
	state.probing = false

	var peer *types.Node
	for i := range d.lastNetmap.Peers {
		if d.lastNetmap.Peers[i].Key == attempt.key {
			peer = &d.lastNetmap.Peers[i]
			break
		}
	}
	if peer == nil ||
		!d.relayed[attempt.key] ||
		!d.discoProbePeerEligibleLocked(*peer) ||
		discoUpgradeFingerprint(*peer) != attempt.fingerprint ||
		!d.relaySince[attempt.key].Equal(attempt.relayCycle) {
		state.permitAt = time.Time{}
		return
	}
	state.nextProbe = now.Add(discoProbeRetry)
	if success {
		state.permitAt = now
	} else {
		// A completed negative result is newer than any previous permission.
		state.permitAt = time.Time{}
	}
}

func (d *Daemon) consumeDiscoUpgradePermitLocked(
	p types.Node,
	stat wgengine.PeerStat,
	now time.Time,
) bool {
	state := d.discoUpgradeStateLocked(p)
	if state.permitAt.IsZero() ||
		now.Before(state.permitAt) ||
		now.Sub(state.permitAt) > discoPermitLifetime {
		state.permitAt = time.Time{}
		return false
	}
	state.permitAt = time.Time{}
	state.directTrial = true
	state.baselineRx = stat.RxBytes
	state.baselineHandshake = stat.LatestHandshake
	return true
}

func (d *Daemon) matchingDiscoDirectTrialLocked(p types.Node) *discoUpgradePeer {
	state := d.discoUpgrades[p.Key]
	if state == nil || !state.directTrial {
		return nil
	}
	if state.fingerprint != discoUpgradeFingerprint(p) {
		delete(d.discoUpgrades, p.Key)
		return nil
	}
	return state
}

func (d *Daemon) markDiscoDirectTrialProvenLocked(state *discoUpgradePeer) {
	state.directTrial = false
	state.trialFailures = 0
	state.nextProbe = time.Time{}
}

func (d *Daemon) markDiscoDirectTrialFailedLocked(p types.Node, now time.Time) {
	state := d.matchingDiscoDirectTrialLocked(p)
	if state == nil {
		return
	}
	state.directTrial = false
	state.trialFailures++
	state.relayCycle = now
	state.permitAt = time.Time{}
	state.nextProbe = now.Add(discoTrialBackoff(state.trialFailures))
}

func discoTrialBackoff(failures int) time.Duration {
	switch failures {
	case 1:
		return 10 * time.Minute
	case 2:
		return 20 * time.Minute
	default:
		return 30 * time.Minute
	}
}

package diagnose

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// coordinatorProbe checks that the control plane is reachable. Per DESIGN.md the
// coordinator being offline degrades new-device onboarding but does not break an
// already-running mesh, so its failures are warnings, not criticals.
type coordinatorProbe struct{}

func (coordinatorProbe) ID() ProbeID { return ProbeCoordinator }

func (coordinatorProbe) Run(ctx context.Context, env *Env) ProbeResult {
	res := ProbeResult{Probe: ProbeCoordinator}
	c := env.Snapshot.Coordinator
	if c.Host == "" {
		res.add(newFinding(ProbeCoordinator, CodeCoordinatorNotConfigured,
			"no coordinator endpoint is configured", nil))
		return res
	}

	addr := endpointHostPort(c, 443)
	conn, err := dialBounded(ctx, env, "tcp", addr)
	if err != nil {
		res.add(newFinding(ProbeCoordinator, CodeCoordinatorUnreachable,
			fmt.Sprintf("could not connect to coordinator at %s", addr),
			map[string]string{"endpoint": addr, "error_class": safeErrorClass(err)}))
		return res
	}
	_ = conn.Close()

	// Optional application-level health check when a scheme is configured.
	if c.Scheme != "" && env.Deps.HTTP != nil {
		status, _, herr := httpGetDrain(ctx, env, endpointURL(c), 4<<10)
		if herr != nil {
			code := CodeCoordinatorUnhealthy
			if looksLikeTLSError(herr) {
				code = CodeCoordinatorTLSError
			}
			res.add(newFinding(ProbeCoordinator, code,
				"coordinator health check failed",
				map[string]string{"endpoint": endpointURL(c), "error_class": safeErrorClass(herr)}))
			return res
		}
		if status < 200 || status >= 400 {
			res.add(newFinding(ProbeCoordinator, CodeCoordinatorUnhealthy,
				fmt.Sprintf("coordinator health check returned HTTP %d", status),
				map[string]string{"endpoint": endpointURL(c), "status": fmt.Sprint(status)}))
			return res
		}
	}

	res.add(newFinding(ProbeCoordinator, CodeCoordinatorOK,
		"coordinator is reachable", map[string]string{"endpoint": addr}))
	return res
}

// looksLikeTLSError heuristically classifies an HTTP error as a TLS handshake
// failure. The abstraction hides the concrete error type, so we match on the
// message; the value itself is redacted before it reaches the report.
func looksLikeTLSError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "tls") ||
		strings.Contains(msg, "certificate") ||
		strings.Contains(msg, "x509") ||
		strings.Contains(msg, "handshake")
}

// relayProbe checks reachability of each configured tenant relay. A single
// reachable relay is enough for censorship-resistant fallback, so the probe
// reports per-relay warnings but only escalates to "none reachable" when every
// configured relay is down.
type relayProbe struct{}

func (relayProbe) ID() ProbeID { return ProbeRelay }

func (relayProbe) Run(ctx context.Context, env *Env) ProbeResult {
	res := ProbeResult{Probe: ProbeRelay}
	relays := env.Snapshot.Relays
	if len(relays) == 0 {
		res.add(newFinding(ProbeRelay, CodeRelayNoneConfigured,
			"no relay is configured", nil))
		return res
	}

	reachable := 0
	for _, r := range relays {
		if ctx.Err() != nil {
			break
		}
		addr := endpointHostPort(r, 443)
		conn, err := dialBounded(ctx, env, "tcp", addr)
		if err != nil {
			res.add(newFinding(ProbeRelay, CodeRelayUnreachable,
				fmt.Sprintf("relay %q is unreachable", r.Label),
				map[string]string{"relay": r.Label, "endpoint": addr, "error_class": safeErrorClass(err)}))
			continue
		}
		_ = conn.Close()
		reachable++
	}

	if reachable == 0 {
		res.add(newFinding(ProbeRelay, CodeRelayNoneReachable,
			"no configured relay is reachable",
			map[string]string{"configured": fmt.Sprint(len(relays))}))
		return res
	}
	res.add(newFinding(ProbeRelay, CodeRelayOK,
		fmt.Sprintf("%d of %d relays reachable", reachable, len(relays)),
		map[string]string{"reachable": fmt.Sprint(reachable), "configured": fmt.Sprint(len(relays))}))
	return res
}

// exitProbe checks the selected exit node's health: handshake freshness, route
// presence, and (optionally) live egress through the tunnel. Exit faults are
// user-impacting, so they are critical.
type exitProbe struct{}

func (exitProbe) ID() ProbeID { return ProbeExit }

func (exitProbe) Run(ctx context.Context, env *Env) ProbeResult {
	res := ProbeResult{Probe: ProbeExit}
	ex := env.Snapshot.Exit
	if ex == nil {
		res.add(newFinding(ProbeExit, CodeExitNotSelected, "no exit is selected", nil))
		return res
	}

	now := env.Clock.Now()
	problem := false

	if stale, age := handshakeStale(now, ex.LastHandshake, env.Config.StaleHandshake); stale {
		problem = true
		res.add(newFinding(ProbeExit, CodeExitHandshakeStale,
			"the exit peer's WireGuard handshake is stale",
			map[string]string{"peer": ex.PeerPublicKey, "handshake_age": age}))
	}
	if !ex.RoutePresent {
		problem = true
		res.add(newFinding(ProbeExit, CodeExitRouteMissing,
			"an exit is selected but its default route is not installed",
			map[string]string{"peer": ex.PeerPublicKey}))
	}

	egressVerified := false
	// Only test live egress when the tunnel looks usable; a stale/route-missing
	// exit will always fail egress and the extra finding adds no signal.
	if !problem {
		switch {
		case ex.EgressCanary == nil:
			res.add(newFinding(ProbeExit, CodeExitEgressNotTested,
				"the exit handshake and route are present, but live egress was not tested",
				map[string]string{"reason": "no_tunnel_bound_canary"}))
		case env.Deps.HTTP == nil:
			res.add(newFinding(ProbeExit, CodeExitEgressNotTested,
				"the exit handshake and route are present, but live egress was not tested",
				map[string]string{"reason": "http_probe_unavailable"}))
		default:
			status, _, err := httpGetDrain(ctx, env, endpointURL(*ex.EgressCanary), 4<<10)
			if err != nil || status < 200 || status >= 400 {
				problem = true
				ev := map[string]string{"canary": ex.EgressCanary.Label}
				if err != nil {
					ev["error_class"] = safeErrorClass(err)
				} else {
					ev["status"] = fmt.Sprint(status)
				}
				res.add(newFinding(ProbeExit, CodeExitEgressBlocked,
					"the exit is selected but egress through it failed", ev))
			} else {
				egressVerified = true
			}
		}
	}

	if !problem && egressVerified {
		res.add(newFinding(ProbeExit, CodeExitOK, "exit is healthy",
			map[string]string{"peer": ex.PeerPublicKey}))
	}
	return res
}

// handshakeStale reports whether a handshake at ts is older than max relative to
// now (a zero ts is always stale), and returns a human age string for evidence.
func handshakeStale(now, ts time.Time, max time.Duration) (bool, string) {
	if ts.IsZero() {
		return true, "never"
	}
	age := now.Sub(ts)
	return age > max, age.Round(time.Second).String()
}

# Design note: non-disruptive relay→direct upgrade

Status: **implemented behind `-disco-probe` for desktop daemons**. The dedicated
responder, endpoint advertisement, and bounded probe-gated relay upgrade are in
place. Mobile clients do not yet publish disco endpoints, so mixed-version and
desktop/mobile peers retain the legacy retry behavior.

## Problem

Once a peer falls back to the relay, the only path back to direct today is the
periodic **blind re-trial** (`checkRelayTransitions`, every `upgradeRetry`=5m):
flip the peer's WG endpoint to direct, watch received bytes for
`relayFallbackAfter`=15s, revert if none. That trial is **disruptive** — while it
runs, traffic goes to the (possibly still-dead) direct endpoint and is lost until
the revert. We want to detect that a direct path has become reachable **without**
disturbing the working relay path, and switch only when confirmed.

## The hard constraint

Under `-tags wgreal`, a **separate process owns the WG UDP port** on `ListenPort`
— kernel WireGuard on Linux, or the `wireguard-go` binary on macOS
(`OwnsListenPort()==true`, `real.go:50`; port-collision note at `daemon.go:213`).
ratelmeshd cannot read or inject packets on it. So Tailscale's approach — disco pings
over the *same* socket, demuxed by a magic prefix — is **not available** to us;
that requires userspace WireGuard (wireguard-go as a *library* with a custom
`conn.Bind`).

State of disco today (corrected after self-review):
- The disco **responder** is skipped under wgreal (`DisableDisco`, set from
  `OwnsListenPort()`), because it would collide with the WG port.
- But `magicsock.ProbeAll` is **not** gated by `DisableDisco`: `refreshPaths`
  (`daemon.go:~520`) already fires it per-peer on every netmap, under wgreal too.
  It always fails (peers run no responder on the WG port) and only sets the
  **cosmetic `pathType` status label** — it does **not** drive routing. The
  relay-upgrade consumer is therefore separate and never feeds a disco-port
  answer into `PeerPath.ConfirmDirect`.

## Options

1. **Separate disco socket on a distinct UDP port** (e.g. `ListenPort+1`).
   Each node runs a small disco responder on that port, advertises it, and probes
   peers' disco ports out-of-band.
   - Pros: non-disruptive (never touches the WG data path); reuses the existing
     `magicsock.DiscoResponder`. Use `magicsock.Probe` (a boolean reachability
     check that mutates no state), **not** `ProbeAll` — `ProbeAll` calls
     `ConfirmDirect`, which would record the answering candidate (a disco address)
     as the peer's WireGuard endpoint. That is wrong: the disco endpoint is not
     the WG endpoint.
   - Cons: under NAT the disco port's mapping differs from the WG port's, so
     disco-port reachability is only a **heuristic** for WG-port reachability —
     reliable for open networks / full-cone NAT / same-LAN, unreliable for
     symmetric NAT.

2. **Cheaper/safer blind trial.** Keep the current re-trial but only trial when
   the peer is idle (low tx) and revert fast. No new sockets, but still a
   (smaller) disruption window and still can't detect reachability without
   trialing.

3. **Userspace WireGuard + custom bind (full magicsock).** The "correct"
   architecture: disco over the WG socket, seamless direct/relay. Big rewrite
   (replaces the external `wg`/kernel path with an in-process wireguard-go device).
   Also unlocks true NAT hole-punching (the other backlog item).

## Recommendation (near-term, tractable)

**Option 1 as a probe *gate* on top of the existing rx-liveness switching** — turn
the blind periodic trial into a **probe-gated** one:

1. Under wgreal, run a disco responder on a dedicated port (un-skip `DisableDisco`
   but bind a *separate* port, not the WG port).
2. Advertise disco endpoints via a **new explicit `Node.DiscoEndpoints`**,
   populated by a STUN query **on the disco socket** (like `GatherEndpoints` does
   for the WG endpoint, `discovery.go`). Do NOT derive them as `wgPort+1`: under
   symmetric/PAT NAT the disco socket gets an independent external port mapping,
   so the offset is wrong in exactly the NAT cases this probe exists to cover.
3. For a **relayed** peer, `Probe` its disco endpoints periodically
   (non-disruptive, no state mutation). Only when a probe **succeeds** do we run
   the existing direct trial → upgrade. On failure, stay on the relay with **no**
   trial. The per-peer state consumed by `checkRelayTransitions` binds the
   one-use permit to the endpoint fingerprint, relay cycle, and latest attempt.

Net effect: the disruptive trial happens only when direct is *likely* reachable,
instead of blindly every 5 minutes. The rx-liveness fallback still corrects a
wrong upgrade within `relayFallbackAfter`, so a heuristic false-positive is
self-healing.

Explicitly documented caveat: disco-port reachability ≠ WG-port reachability under
symmetric NAT; this is a heuristic, not a guarantee. The true fix is Option 3.

## Deferred

Option 3 (userspace WireGuard) is the real, non-heuristic solution and the
prerequisite for NAT hole-punching. It is a large, separate effort — **not** to be
started autonomously overnight. Tracked as its own backlog item.

## Proposed implementation sub-steps (each its own small, self-reviewed commit)

1. (this note) design + review.
2. `magicsock`: allow a disco responder on an explicit port under wgreal; unit
   test responder + `Probe` over loopback on a non-WG port.
3. `types`: add `Node.DiscoEndpoints` (optional; empty = no disco). Coord passes
   them through; no behavior change yet.
4. daemon: run the responder under wgreal on `ListenPort+1`, STUN the disco socket
   to fill `DiscoEndpoints`, and advertise them.
5. **Implemented.** daemon: add per-peer probe state and gate the relay→direct trial in
   `checkRelayTransitions` on a successful `Probe` of the peer's disco endpoints;
   keep strict post-switch WireGuard rx/handshake liveness as the safety net.
   Probe work is capped globally, stale results are bound to the endpoint set and
   relay cycle, and repeated disco/WireGuard mismatches back off.
6. E2E: a topology where direct becomes reachable, proving upgrade fires only
   after a successful probe (and never disrupts a healthy relay path).

Steps 2–6 are independent and revertible; stop and hand to a human if any step
turns out to need the Option-3 rewrite instead.

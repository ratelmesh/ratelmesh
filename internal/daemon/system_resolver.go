package daemon

import (
	"context"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/dns"
)

const systemResolverRetryInterval = 2 * time.Second

// superviseSystemResolver keeps retrying the initial system-resolver takeover
// until the host has a usable primary network service. launchd commonly starts
// the daemon before Wi-Fi or Ethernet has installed a default route; treating
// that transient state as permanent leaves macOS sending DNS to an unreachable
// physical resolver after EXIT routes become active.
func (d *Daemon) superviseSystemResolver(
	ctx context.Context,
	resolver dns.SystemResolver,
	serverIP string,
	retry <-chan time.Time,
) {
	attempt := 0
	for {
		attempt++
		// Re-discover physical resolvers on every attempt. The same launch-time
		// race that hides the primary service also leaves the initial forwarding
		// set empty; without refreshing it, switching EXIT -> DIRECT makes
		// MagicDNS answer public names with NXDOMAIN.
		systemUpstreams := resolver.CurrentUpstreams()
		if len(systemUpstreams) == 0 {
			if attempt == 1 {
				d.log.Warn("system resolver takeover deferred", "reason", "no usable physical DNS upstream")
			} else {
				d.log.Debug("system resolver takeover still unavailable", "attempt", attempt, "reason", "no usable physical DNS upstream")
			}
		} else if err := resolver.Install(serverIP); err == nil {
			d.mu.Lock()
			d.systemResolver = resolver
			d.dnsSystemUpstrms = append([]string(nil), systemUpstreams...)
			srv := d.dnsServer
			tunnelMode := d.dnsModeKnown && d.dnsTunnelMode
			directUpstreams := append([]string(nil), d.dnsSystemUpstrms...)
			tunnelUpstream := normalizeResolver(d.cfg.TunnelDNS)
			d.mu.Unlock()
			if srv != nil {
				if tunnelMode && d.cfg.TunnelDNS != "" {
					srv.SetUpstreams([]string{tunnelUpstream})
				} else {
					srv.SetUpstreams(directUpstreams)
				}
			}
			if attempt == 1 {
				d.log.Info("system resolver now points at MagicDNS", "server", serverIP)
			} else {
				d.log.Info("system resolver takeover recovered", "server", serverIP, "attempts", attempt)
			}

			<-ctx.Done()
			if err := resolver.Restore(); err != nil {
				d.log.Warn("system resolver restore failed", "err", err)
			}
			d.mu.Lock()
			if d.systemResolver == resolver {
				d.systemResolver = nil
			}
			d.mu.Unlock()
			return
		} else if attempt == 1 {
			d.log.Warn("system resolver takeover deferred", "err", err)
		} else {
			d.log.Debug("system resolver takeover still unavailable", "attempt", attempt, "err", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-retry:
		}
	}
}

func (d *Daemon) startSystemResolverSupervisor(
	ctx context.Context,
	resolver dns.SystemResolver,
	serverIP string,
) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(systemResolverRetryInterval)
		defer ticker.Stop()
		d.superviseSystemResolver(ctx, resolver, serverIP, ticker.C)
	}()
	return done
}

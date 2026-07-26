// Package doctorplatform captures bounded, read-only operating-system network
// state for the Network Doctor.
package doctorplatform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/diagnose"
)

const captureTimeout = 6 * time.Second

const (
	maxInterfaces = 4096
	maxAddresses  = 16384
)

// Inputs contains daemon-owned state which must survive platform enrichment.
type Inputs struct {
	Snapshot diagnose.Snapshot
}

// Observation identifies one independently captured operating-system field.
type Observation string

const (
	ObservationInterfaces Observation = "interfaces"
	ObservationRoutes     Observation = "routes"
	ObservationDNS        Observation = "dns"
	ObservationTunnelMTU  Observation = "tunnel_mtu"
)

// ErrorKind is a stable, non-sensitive observation failure category.
type ErrorKind string

const (
	ErrorUnavailable ErrorKind = "unavailable"
	ErrorTimeout     ErrorKind = "timeout"
	ErrorCanceled    ErrorKind = "canceled"
	ErrorInvalid     ErrorKind = "invalid_input"
	ErrorOversized   ErrorKind = "oversized"
	ErrorMalformed   ErrorKind = "malformed"
)

// ObservationError reports why one field could not be captured. It never
// contains command output, addresses, domains, paths supplied by callers, or
// other network identifiers.
type ObservationError struct {
	Observation Observation
	Kind        ErrorKind
}

func (e ObservationError) Error() string {
	return fmt.Sprintf("doctor platform observation %s: %s", e.Observation, e.Kind)
}

// Collector is a production-safe, read-only snapshot collector.
type Collector struct {
	runner     commandRunner
	readFile   boundedFileReader
	interfaces interfaceSource
	ops        platformOps
}

// New returns the collector for the current operating system.
func New() *Collector {
	return &Collector{
		runner:     execRunner{},
		readFile:   osFileReader{},
		interfaces: systemInterfaces,
		ops:        currentPlatformOps(),
	}
}

// newCollector is intentionally unexported: only package tests may inject
// command, file, and interface sources.
func newCollector(r commandRunner, f boundedFileReader, ifs interfaceSource, ops platformOps) *Collector {
	return &Collector{runner: r, readFile: f, interfaces: ifs, ops: ops}
}

// Capture preserves all caller-supplied daemon state and enriches only the
// operating-system-owned Addresses, Routes, DNS, and WireGuard.LinkMTU fields.
// Independent failures return a partial snapshot plus typed observation errors.
func (c *Collector) Capture(ctx context.Context, in Inputs) (diagnose.Snapshot, []ObservationError) {
	snap := in.Snapshot
	// OS-owned fields must never inherit a previously healthy observation. A
	// failed refresh stays explicitly unknown rather than making stale state
	// look safe.
	snap.Addresses = nil
	snap.Routes = nil
	snap.DNS = diagnose.DNSState{}
	snap.WireGuard.LinkMTU = 0
	if ctx == nil {
		observationErrors := []ObservationError{
			{Observation: ObservationInterfaces, Kind: ErrorInvalid},
			{Observation: ObservationRoutes, Kind: ErrorInvalid},
			{Observation: ObservationDNS, Kind: ErrorInvalid},
		}
		if snap.WireGuard.Interface != "" {
			observationErrors = append(observationErrors, ObservationError{
				Observation: ObservationTunnelMTU,
				Kind:        ErrorInvalid,
			})
		}
		return snap, observationErrors
	}
	if c == nil {
		return snap, []ObservationError{{Observation: ObservationInterfaces, Kind: ErrorUnavailable}}
	}

	ctx, cancel := context.WithTimeout(ctx, captureTimeout)
	defer cancel()

	var observationErrors []ObservationError
	infos, err := c.interfaces()
	if err != nil {
		observationErrors = append(observationErrors, ObservationError{
			Observation: ObservationInterfaces,
			Kind:        classifyError(ctx, err),
		})
	} else {
		addresses, addrErr := interfaceAddresses(infos)
		if addrErr != nil {
			observationErrors = append(observationErrors, ObservationError{
				Observation: ObservationInterfaces,
				Kind:        classifyError(ctx, addrErr),
			})
		} else {
			snap.Addresses = addresses
		}
	}

	if snap.WireGuard.Interface != "" {
		if err != nil {
			observationErrors = append(observationErrors, ObservationError{
				Observation: ObservationTunnelMTU,
				Kind:        classifyError(ctx, err),
			})
		} else if mtu, ok := interfaceMTU(infos, snap.WireGuard.Interface); ok {
			snap.WireGuard.LinkMTU = mtu
		} else {
			observationErrors = append(observationErrors, ObservationError{
				Observation: ObservationTunnelMTU,
				Kind:        ErrorUnavailable,
			})
		}
	}

	routes, err := c.ops.routes(ctx, c.runner, infos, snap.WireGuard.Interface)
	if len(routes) > 0 {
		snap.Routes = routes
	}
	if err != nil {
		observationErrors = append(observationErrors, ObservationError{
			Observation: ObservationRoutes,
			Kind:        classifyError(ctx, err),
		})
	} else if routes != nil {
		snap.Routes = routes
	}

	dns, err := c.ops.dns(ctx, c.runner, c.readFile, snap.WireGuard.Interface)
	if err != nil {
		observationErrors = append(observationErrors, ObservationError{
			Observation: ObservationDNS,
			Kind:        classifyError(ctx, err),
		})
	} else {
		snap.DNS = dns
	}
	return snap, observationErrors
}

type interfaceInfo struct {
	Index int
	Name  string
	MTU   int
	Addrs []string
}

type interfaceSource func() ([]interfaceInfo, error)

func systemInterfaces() ([]interfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, errors.New("list interfaces")
	}
	if len(ifaces) > maxInterfaces {
		return nil, errOversized
	}
	out := make([]interfaceInfo, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			return nil, errors.New("list interface addresses")
		}
		info := interfaceInfo{Index: iface.Index, Name: iface.Name, MTU: iface.MTU}
		for _, addr := range addrs {
			if len(info.Addrs) >= maxAddresses {
				return nil, errOversized
			}
			info.Addrs = append(info.Addrs, addr.String())
		}
		out = append(out, info)
	}
	return out, nil
}

func interfaceAddresses(infos []interfaceInfo) ([]diagnose.InterfaceAddr, error) {
	var out []diagnose.InterfaceAddr
	for _, info := range infos {
		if info.Name == "" || len(info.Name) > 256 {
			return nil, errMalformed
		}
		for _, raw := range info.Addrs {
			prefix, err := netip.ParsePrefix(withoutZone(raw))
			if err != nil {
				addr, addrErr := netip.ParseAddr(withoutZone(raw))
				if addrErr != nil {
					return nil, errMalformed
				}
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			addr := prefix.Addr().Unmap()
			family := diagnose.FamilyV6
			if addr.Is4() {
				family = diagnose.FamilyV4
			}
			out = append(out, diagnose.InterfaceAddr{
				Interface: info.Name,
				Family:    family,
				Addr:      addr,
			})
			if len(out) > maxAddresses {
				return nil, errOversized
			}
		}
	}
	return out, nil
}

func withoutZone(raw string) string {
	percent := strings.IndexByte(raw, '%')
	if percent < 0 {
		return raw
	}
	slash := strings.IndexByte(raw[percent:], '/')
	if slash < 0 {
		return raw[:percent]
	}
	return raw[:percent] + raw[percent+slash:]
}

func interfaceMTU(infos []interfaceInfo, name string) (int, bool) {
	for _, info := range infos {
		if info.Name == name && info.MTU > 0 && info.MTU <= 1<<20 {
			return info.MTU, true
		}
	}
	return 0, false
}

func classifyError(ctx context.Context, err error) ErrorKind {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(ctx.Err(), context.Canceled):
		return ErrorCanceled
	case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return ErrorTimeout
	case errors.Is(err, errOversized):
		return ErrorOversized
	case errors.Is(err, errMalformed):
		return ErrorMalformed
	default:
		return ErrorUnavailable
	}
}

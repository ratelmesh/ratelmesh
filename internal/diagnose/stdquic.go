package diagnose

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/quic"
)

var (
	errQUICEndpoint  = errors.New("QUIC endpoint unavailable")
	errQUICHandshake = errors.New("TLS-over-QUIC HTTP/3 handshake failed")
)

// stdQUICProber establishes a real QUIC connection with certificate
// verification and requires ALPN h3. Merely opening or writing to a UDP socket
// is deliberately insufficient: that would not prove a return path or QUIC.
type stdQUICProber struct {
	// roots is nil in production, which uses the host trust store. Package tests
	// inject a private root to exercise a real local QUIC handshake.
	roots    *x509.CertPool
	resolver Resolver
}

func (p stdQUICProber) ProbeQUIC(ctx context.Context, host string, port int) error {
	if ctx == nil || strings.TrimSpace(host) != host || host == "" || port < 1 || port > 65535 {
		return errQUICEndpoint
	}
	serverName := strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), ".")
	if serverName == "" {
		return errQUICEndpoint
	}

	targets, err := p.resolveTargets(ctx, serverName, port)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return errQUICEndpoint
	}
	return p.probeTargets(ctx, serverName, targets)
}

type quicTarget struct {
	network string
	local   string
	remote  string
}

func (p stdQUICProber) resolveTargets(ctx context.Context, host string, port int) ([]quicTarget, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if literal, err := netip.ParseAddr(host); err == nil {
		return []quicTarget{targetForIP(literal, port)}, nil
	}
	resolver := p.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addrs, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	const maxQUICAddresses = 4
	const maxResolvedRecords = 64
	v4 := make([]netip.Addr, 0, maxQUICAddresses)
	v6 := make([]netip.Addr, 0, maxQUICAddresses)
	for i, addr := range addrs {
		if i == maxResolvedRecords {
			break
		}
		addr = addr.Unmap()
		if !addr.IsValid() {
			continue
		}
		bucket := &v6
		if addr.Is4() {
			bucket = &v4
		}
		if len(*bucket) < maxQUICAddresses && !containsQUICAddr(*bucket, addr) {
			*bucket = append(*bucket, addr)
		}
		if len(v4) == maxQUICAddresses && len(v6) == maxQUICAddresses {
			break
		}
	}
	selected := make([]netip.Addr, 0, maxQUICAddresses)
	if len(v4) != 0 && len(v6) != 0 {
		// Reserve half the bounded race for each available family. DNS answer
		// order must not let several dead AAAA records evict every usable A
		// record (or vice versa) before Happy Eyeballs begins.
		selected = append(selected, v4[:min(2, len(v4))]...)
		selected = append(selected, v6[:min(2, len(v6))]...)
	} else if len(v4) != 0 {
		selected = append(selected, v4...)
	} else {
		selected = append(selected, v6...)
	}
	targets := make([]quicTarget, 0, len(selected))
	for _, addr := range selected {
		targets = append(targets, targetForIP(addr, port))
	}
	if len(targets) == 0 {
		return nil, errQUICEndpoint
	}
	return targets, nil
}

func containsQUICAddr(addrs []netip.Addr, candidate netip.Addr) bool {
	for _, addr := range addrs {
		if addr == candidate {
			return true
		}
	}
	return false
}

// probeTargets performs a bounded Happy-Eyeballs race. A silent first AAAA (or
// A) record must not consume the whole handshake deadline and suppress another
// working family/address. The result channel is fully buffered, every attempt
// is joined, and each attempt closes its endpoint before reporting, so success
// or cancellation cannot leave background probe resources behind.
func (p stdQUICProber) probeTargets(ctx context.Context, serverName string, targets []quicTarget) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	raceCtx, cancel := context.WithCancel(ctx)
	results := make(chan error, len(targets))
	var attempts sync.WaitGroup
	for _, target := range targets {
		attempts.Add(1)
		go func() {
			defer attempts.Done()
			results <- p.probeTarget(raceCtx, serverName, target)
		}()
	}
	success := false
	for range targets {
		if err := <-results; err == nil && !success {
			success = true
			cancel()
		}
	}
	cancel()
	attempts.Wait()
	if success {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return errQUICHandshake
}

func targetForIP(addr netip.Addr, port int) quicTarget {
	target := quicTarget{
		network: "udp6",
		local:   "[::]:0",
		remote:  net.JoinHostPort(addr.String(), strconv.Itoa(port)),
	}
	if addr.Is4() {
		target.network = "udp4"
		target.local = "0.0.0.0:0"
	}
	return target
}

func (p stdQUICProber) probeTarget(ctx context.Context, serverName string, target quicTarget) error {
	endpoint, err := quic.Listen(target.network, target.local, nil)
	if err != nil {
		return errQUICEndpoint
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 250*time.Millisecond)
		defer cancel()
		_ = endpoint.Close(cleanupCtx)
	}()

	conn, err := endpoint.Dial(ctx, target.network, target.remote, &quic.Config{
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: serverName,
			NextProtos: []string{"h3"},
			RootCAs:    p.roots,
		},
		HandshakeTimeout:         0, // the caller's stricter context is authoritative
		MaxIdleTimeout:           time.Second,
		MaxBidiRemoteStreams:     -1,
		MaxUniRemoteStreams:      -1,
		MaxConnReadBufferSize:    64 << 10,
		MaxStreamReadBufferSize:  16 << 10,
		MaxStreamWriteBufferSize: 16 << 10,
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return errQUICHandshake
	}
	defer conn.Abort(nil)

	state := conn.ConnectionState()
	if !state.HandshakeComplete || state.NegotiatedProtocol != "h3" {
		return errQUICHandshake
	}
	return nil
}

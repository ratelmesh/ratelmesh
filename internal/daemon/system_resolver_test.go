package daemon

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/dns"
)

type retryingResolver struct {
	mu             sync.Mutex
	failures       int
	installs       int
	restores       int
	installAttempt chan int
	upstreams      []string
	upstreamReads  int
	upstreamRead   chan int
}

func (r *retryingResolver) CurrentUpstreams() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.upstreamReads++
	select {
	case r.upstreamRead <- r.upstreamReads:
	default:
	}
	return append([]string(nil), r.upstreams...)
}

func (r *retryingResolver) Install(string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.installs++
	select {
	case r.installAttempt <- r.installs:
	default:
	}
	if r.installs <= r.failures {
		return errors.New("no default interface")
	}
	return nil
}

func (r *retryingResolver) Restore() error {
	r.mu.Lock()
	r.restores++
	r.mu.Unlock()
	return nil
}

func (*retryingResolver) FlushCache() error { return nil }

func (r *retryingResolver) counts() (installs, restores int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.installs, r.restores
}

func (r *retryingResolver) setUpstreams(upstreams ...string) {
	r.mu.Lock()
	r.upstreams = append([]string(nil), upstreams...)
	r.mu.Unlock()
}

func waitResolverAttempt(t *testing.T, attempts <-chan int, want int) {
	t.Helper()
	select {
	case got := <-attempts:
		if got != want {
			t.Fatalf("resolver attempt = %d, want %d", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for resolver attempt %d", want)
	}
}

func TestSystemResolverRetriesTransientStartupFailure(t *testing.T) {
	srv, err := dns.NewServer(dns.NewZone(""), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	resolver := &retryingResolver{
		failures:       2,
		installAttempt: make(chan int, 3),
		upstreams:      []string{"192.0.2.53:53"},
	}
	d := &Daemon{
		cfg:       Config{TunnelDNS: "1.1.1.1:53", ManageResolv: true},
		log:       slog.Default(),
		dnsServer: srv,
	}
	ctx, cancel := context.WithCancel(context.Background())
	retry := make(chan time.Time, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.superviseSystemResolver(ctx, resolver, "127.0.0.1", retry)
	}()

	waitResolverAttempt(t, resolver.installAttempt, 1)
	if got := d.effectiveDNS(true); got != "system" {
		t.Fatalf("DNS before system takeover = %q, want system", got)
	}
	retry <- time.Now()
	waitResolverAttempt(t, resolver.installAttempt, 2)
	retry <- time.Now()
	waitResolverAttempt(t, resolver.installAttempt, 3)
	deadline := time.Now().Add(time.Second)
	for d.effectiveDNS(true) != "1.1.1.1:53" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := d.effectiveDNS(true); got != "1.1.1.1:53" {
		t.Fatalf("DNS after recovered takeover = %q, want tunnel resolver", got)
	}
	d.mu.Lock()
	systemUpstreams := append([]string(nil), d.dnsSystemUpstrms...)
	d.mu.Unlock()
	if len(systemUpstreams) != 1 || systemUpstreams[0] != "192.0.2.53:53" {
		t.Fatalf("refreshed direct upstreams = %v, want physical resolver", systemUpstreams)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("resolver supervisor did not stop")
	}
	installs, restores := resolver.counts()
	if installs != 3 || restores != 1 {
		t.Fatalf("resolver lifecycle installs=%d restores=%d, want 3/1", installs, restores)
	}
	if got := d.effectiveDNS(true); got != "system" {
		t.Fatalf("DNS after restore = %q, want system", got)
	}
}

func TestSystemResolverWaitsForPhysicalUpstreamBeforeTakeover(t *testing.T) {
	srv, err := dns.NewServer(dns.NewZone(""), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	resolver := &retryingResolver{
		installAttempt: make(chan int, 1),
		upstreamRead:   make(chan int, 2),
	}
	d := &Daemon{
		cfg:       Config{TunnelDNS: "1.1.1.1:53", ManageResolv: true},
		log:       slog.Default(),
		dnsServer: srv,
	}
	ctx, cancel := context.WithCancel(context.Background())
	retry := make(chan time.Time, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.superviseSystemResolver(ctx, resolver, "127.0.0.1", retry)
	}()

	waitResolverAttempt(t, resolver.upstreamRead, 1)
	if installs, _ := resolver.counts(); installs != 0 {
		t.Fatalf("resolver installed without a physical upstream: installs=%d", installs)
	}
	if got := d.effectiveDNS(true); got != "system" {
		t.Fatalf("DNS before physical upstream = %q, want system", got)
	}

	resolver.setUpstreams("192.0.2.53:53")
	retry <- time.Now()
	waitResolverAttempt(t, resolver.upstreamRead, 2)
	waitResolverAttempt(t, resolver.installAttempt, 1)

	deadline := time.Now().Add(time.Second)
	for d.effectiveDNS(true) != "1.1.1.1:53" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	d.mu.Lock()
	systemUpstreams := append([]string(nil), d.dnsSystemUpstrms...)
	d.mu.Unlock()
	if len(systemUpstreams) != 1 || systemUpstreams[0] != "192.0.2.53:53" {
		t.Fatalf("direct upstreams after DHCP recovery = %v, want physical resolver", systemUpstreams)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("resolver supervisor did not stop")
	}
	installs, restores := resolver.counts()
	if installs != 1 || restores != 1 {
		t.Fatalf("resolver lifecycle installs=%d restores=%d, want 1/1", installs, restores)
	}
}

func TestSystemResolverCancellationBeforeInstallDoesNotRestore(t *testing.T) {
	resolver := &retryingResolver{
		failures:       10,
		installAttempt: make(chan int, 1),
		upstreams:      []string{"192.0.2.53:53"},
	}
	d := &Daemon{log: slog.Default()}
	ctx, cancel := context.WithCancel(context.Background())
	retry := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.superviseSystemResolver(ctx, resolver, "127.0.0.1", retry)
	}()

	waitResolverAttempt(t, resolver.installAttempt, 1)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("resolver supervisor did not stop")
	}
	installs, restores := resolver.counts()
	if installs != 1 || restores != 0 {
		t.Fatalf("resolver lifecycle installs=%d restores=%d, want 1/0", installs, restores)
	}
}

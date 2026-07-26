package daemon

import (
	"log/slog"
	"testing"

	"github.com/ratelmesh/ratelmesh/internal/dns"
)

type cacheCountingResolver struct{ flushes int }

func (*cacheCountingResolver) CurrentUpstreams() []string { return nil }
func (*cacheCountingResolver) Install(string) error       { return nil }
func (*cacheCountingResolver) Restore() error             { return nil }
func (r *cacheCountingResolver) FlushCache() error {
	r.flushes++
	return nil
}

func TestDNSModeSwitchFlushesSystemCache(t *testing.T) {
	srv, err := dns.NewServer(dns.NewZone(""), "127.0.0.1:0", "192.0.2.53:53")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	resolver := &cacheCountingResolver{}
	d := &Daemon{
		cfg:              Config{TunnelDNS: "1.1.1.1:53"},
		log:              slog.Default(),
		dnsServer:        srv,
		dnsSystemUpstrms: []string{"192.0.2.53:53"},
		systemResolver:   resolver,
	}

	d.updateDNSUpstreams(false) // initial local/system mode
	d.updateDNSUpstreams(false) // unchanged: do not churn the system cache
	if resolver.flushes != 1 {
		t.Fatalf("initial/unchanged flushes = %d, want 1", resolver.flushes)
	}
	d.updateDNSUpstreams(true)
	d.updateDNSUpstreams(true)
	if resolver.flushes != 2 {
		t.Fatalf("tunnel/unchanged flushes = %d, want 2", resolver.flushes)
	}
	d.updateDNSUpstreams(false)
	if resolver.flushes != 3 {
		t.Fatalf("return-to-system flushes = %d, want 3", resolver.flushes)
	}
}

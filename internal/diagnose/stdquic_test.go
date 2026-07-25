package diagnose

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/quic"
)

func TestStdQUICProberRequiresVerifiedH3Handshake(t *testing.T) {
	t.Run("verified h3", func(t *testing.T) {
		host, port, roots := localQUICServer(t, []string{"h3"})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := (stdQUICProber{roots: roots}).ProbeQUIC(ctx, host, port); err != nil {
			t.Fatalf("verified h3 handshake failed: %v", err)
		}
	})

	t.Run("different ALPN is not HTTP3 capability", func(t *testing.T) {
		host, port, roots := localQUICServer(t, []string{"not-h3"})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := (stdQUICProber{roots: roots}).ProbeQUIC(ctx, host, port); err == nil {
			t.Fatal("QUIC transport without ALPN h3 counted as HTTP/3 capability")
		}
	})

	t.Run("invalid target fails without network activity", func(t *testing.T) {
		if err := (stdQUICProber{}).ProbeQUIC(context.Background(), "", 443); err == nil {
			t.Fatal("empty QUIC host accepted")
		}
		if err := (stdQUICProber{}).ProbeQUIC(context.Background(), "example.com", 0); err == nil {
			t.Fatal("invalid QUIC port accepted")
		}
	})
}

func TestStdQUICProberCancelsHostnameResolution(t *testing.T) {
	resolver := &blockingQUICResolver{
		started:  make(chan struct{}),
		returned: make(chan struct{}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := (stdQUICProber{resolver: resolver}).ProbeQUIC(ctx, "blocked.example", 443)
	if err == nil || ctx.Err() == nil {
		t.Fatalf("blocked resolution was not canceled: err=%v ctx=%v", err, ctx.Err())
	}
	select {
	case <-resolver.returned:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("resolver goroutine remained blocked after probe deadline")
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("canceled resolution returned too slowly: %s", elapsed)
	}
}

func TestStdQUICProberRetainsFallbackFamilyPastAddressCap(t *testing.T) {
	_, port, roots := localQUICServer(t, []string{"h3"})
	silent, err := net.ListenPacket("udp6", net.JoinHostPort("::1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = silent.Close() })

	resolver := staticQUICResolver{addrs: []netip.Addr{
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("2001:db8::3"),
		netip.MustParseAddr("2001:db8::4"),
		netip.MustParseAddr("127.0.0.1"),
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	if err := (stdQUICProber{roots: roots, resolver: resolver}).ProbeQUIC(ctx, "example.com", port); err != nil {
		t.Fatalf("working IPv4 was evicted by earlier IPv6 answers: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Happy Eyeballs waited on the silent IPv6 family: %s", elapsed)
	}
}

type staticQUICResolver struct {
	addrs []netip.Addr
}

func (r staticQUICResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r.addrs...), nil
}

type blockingQUICResolver struct {
	once     sync.Once
	started  chan struct{}
	returned chan struct{}
}

func (r *blockingQUICResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	r.once.Do(func() { close(r.started) })
	<-ctx.Done()
	close(r.returned)
	return nil, ctx.Err()
}

func localQUICServer(t *testing.T, nextProtos []string) (string, int, *x509.CertPool) {
	t.Helper()
	tlsServer := httptest.NewTLSServer(nil)
	certificate := tlsServer.TLS.Certificates[0]
	leafDER := certificate.Certificate[0]
	tlsServer.Close()

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	endpoint, err := quic.Listen("udp4", "127.0.0.1:0", &quic.Config{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			NextProtos:   nextProtos,
			MinVersion:   tls.VersionTLS13,
		},
		HandshakeTimeout: 2 * time.Second,
		MaxIdleTimeout:   time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = endpoint.Close(ctx)
	})

	acceptCtx, cancelAccept := context.WithCancel(context.Background())
	t.Cleanup(cancelAccept)
	go func() {
		conn, acceptErr := endpoint.Accept(acceptCtx)
		if acceptErr == nil {
			conn.Abort(nil)
		}
	}()

	host, portText, err := net.SplitHostPort(endpoint.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return host, port, roots
}

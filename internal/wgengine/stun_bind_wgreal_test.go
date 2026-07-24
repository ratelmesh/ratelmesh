//go:build wgreal

package wgengine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/magicsock"
	"golang.zx2c4.com/wireguard/conn"
)

func TestSTUNBindDiscoversItsWireGuardSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := magicsock.ListenSTUN("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go server.Serve(ctx)

	bind := newSTUNBind(conn.NewDefaultBind())
	receivers, port, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	for _, receive := range receivers {
		go func(fn conn.ReceiveFunc) {
			packets := make([][]byte, bind.BatchSize())
			for i := range packets {
				packets[i] = make([]byte, 2048)
			}
			sizes := make([]int, len(packets))
			eps := make([]conn.Endpoint, len(packets))
			for {
				if _, err := fn(packets, sizes, eps); err != nil && !errors.Is(err, net.ErrClosed) {
					return
				}
			}
		}(receive)
	}
	discoverCtx, discoverCancel := context.WithTimeout(ctx, 2*time.Second)
	defer discoverCancel()
	mapped, err := bind.Discover(discoverCtx, server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if mapped.Port() != port {
		t.Fatalf("mapped port = %d, WireGuard bind port = %d", mapped.Port(), port)
	}
}

func TestSTUNBindProbesPeerThroughWireGuardSocket(t *testing.T) {
	left := newSTUNBind(conn.NewDefaultBind())
	right := newSTUNBind(conn.NewDefaultBind())
	leftReceivers, leftPort, err := left.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	rightReceivers, rightPort, err := right.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer right.Close()
	runBindReceivers(left, leftReceivers)
	runBindReceivers(right, rightReceivers)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := left.Probe(ctx, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), rightPort)); err != nil {
		t.Fatalf("left -> right probe failed: %v", err)
	}
	if err := right.Probe(ctx, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), leftPort)); err != nil {
		t.Fatalf("right -> left probe failed: %v", err)
	}
}

func runBindReceivers(bind *stunBind, receivers []conn.ReceiveFunc) {
	for _, receive := range receivers {
		go func(fn conn.ReceiveFunc) {
			packets := make([][]byte, bind.BatchSize())
			for i := range packets {
				packets[i] = make([]byte, 2048)
			}
			sizes := make([]int, len(packets))
			eps := make([]conn.Endpoint, len(packets))
			for {
				if _, err := fn(packets, sizes, eps); err != nil {
					return
				}
			}
		}(receive)
	}
}

func TestResolveSTUNEndpointAcceptsHostname(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got, err := resolveSTUNEndpoint(ctx, "localhost:3478")
	if err != nil {
		t.Fatal(err)
	}
	if got.Port() != 3478 || !got.Addr().IsLoopback() {
		t.Fatalf("resolved endpoint = %s", got)
	}
}

func TestResolveSTUNEndpointKeepsNumericAddress(t *testing.T) {
	want := netip.MustParseAddrPort("192.0.2.10:3478")
	got, err := resolveSTUNEndpoint(context.Background(), want.String())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("resolved endpoint = %s, want %s", got, want)
	}
}

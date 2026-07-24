package magicsock

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDiscoverReflexiveFromStablePort(t *testing.T) {
	stun, err := ListenSTUN("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stun.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = stun.Serve(ctx) }()

	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(probe.LocalAddr().(*net.UDPAddr).Port)
	probe.Close()

	discoverCtx, discoverCancel := context.WithTimeout(ctx, 2*time.Second)
	defer discoverCancel()
	got, err := DiscoverReflexiveFromPort(discoverCtx, port, stun.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if got.Port() != port || !got.Addr().IsLoopback() {
		t.Fatalf("reflexive endpoint = %v, want loopback port %d", got, port)
	}
}

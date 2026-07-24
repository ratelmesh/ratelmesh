package dns

import (
	"reflect"
	"testing"
)

func TestParseDarwinDNSUpstreamsExcludesLocalResolver(t *testing.T) {
	input := `resolver #1
  nameserver[0] : 127.0.0.1
  nameserver[1] : 8.8.8.8
resolver #2
  nameserver[0] : ::1
  nameserver[1] : 2606:4700:4700::1111
resolver #3
  nameserver[0] : 8.8.8.8
`
	got := parseDarwinDNSUpstreams(input)
	want := []string{"8.8.8.8:53", "[2606:4700:4700::1111]:53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("upstreams = %v, want %v", got, want)
	}
}

func TestParseDarwinDHCPDNS(t *testing.T) {
	input := `op = BOOTREPLY
yiaddr = 192.168.1.200
domain_name_server (ip_mult): {192.168.1.254, 1.1.1.1}
`
	got := parseDarwinDHCPDNS(input)
	want := []string{"192.168.1.254:53", "1.1.1.1:53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DHCP upstreams = %v, want %v", got, want)
	}
}

func TestOnlyLoopbackDNS(t *testing.T) {
	if !onlyLoopbackDNS([]string{"127.0.0.1", "::1"}) {
		t.Fatal("loopback-only DNS was not detected")
	}
	if onlyLoopbackDNS([]string{"127.0.0.1", "192.168.1.1"}) {
		t.Fatal("mixed DNS was treated as loopback-only")
	}
}

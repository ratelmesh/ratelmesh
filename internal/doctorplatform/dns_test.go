package doctorplatform

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestParseResolvConfIPv4IPv6Search(t *testing.T) {
	state, err := parseResolvConf([]byte(`
# generated
nameserver 1.1.1.1
nameserver 2001:4860:4860::8888
search corp.example dev.example.
options edns0
`), "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Servers) != 2 ||
		state.Servers[0] != netip.MustParseAddr("1.1.1.1") ||
		state.Servers[1] != netip.MustParseAddr("2001:4860:4860::8888") ||
		len(state.SearchDomains) != 2 {
		t.Fatalf("state = %+v", state)
	}
}

func TestParseDarwinDNSViaTunnel(t *testing.T) {
	input := []byte(`DNS configuration

resolver #1
  search domain[0] : corp.example
  nameserver[0] : 100.64.0.1
  nameserver[1] : fd00::1
  if_index : 18 (utun7)
  flags    : Request A records
`)
	state, err := parseDarwinDNS(input, "utun7")
	if err != nil {
		t.Fatal(err)
	}
	if !state.ViaTunnel || len(state.Servers) != 2 || len(state.SearchDomains) != 1 {
		t.Fatalf("state = %+v", state)
	}
}

func TestParseWindowsDNS(t *testing.T) {
	input := []byte(`Windows IP Configuration

   DNS Suffix Search List. . . . . . : corp.example
                                       dev.example

Ethernet adapter Ethernet:
   Connection-specific DNS Suffix  . : lan.example
   DNS Servers . . . . . . . . . . : 192.0.2.53

Unknown adapter wg0:
   DNS Servers . . . . . . . . . . : 100.64.0.1
                                       fd00::1
`)
	state, err := parseWindowsDNS(input, "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Servers) != 3 || len(state.SearchDomains) != 3 || state.ViaTunnel {
		t.Fatalf("state = %+v", state)
	}
}

func TestParseWindowsDNSAllResolversOnTunnel(t *testing.T) {
	input := []byte(`Windows IP Configuration

Unknown adapter wg0:
   DNS Servers . . . . . . . . . . : 100.64.0.1
                                       fd00::1
`)
	state, err := parseWindowsDNS(input, "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if !state.ViaTunnel || len(state.Servers) != 2 {
		t.Fatalf("state = %+v", state)
	}
}

func TestParseWindowsDNSLocalizedOutputFailsClosed(t *testing.T) {
	input := []byte(`Windows-IP-Konfiguration

Ethernet-Adapter Ethernet:
   DNS-Server  . . . . . . . . . . : 192.0.2.53
`)
	if _, err := parseWindowsDNS(input, "wg0"); err == nil {
		t.Fatal("unrecognized localized ipconfig output was accepted")
	}
}

func TestDNSParsersRejectMalformedAndOversized(t *testing.T) {
	cases := []struct {
		name string
		fn   func([]byte) error
		data []byte
	}{
		{"resolv malformed IP", func(b []byte) error { _, err := parseResolvConf(b, "wg0"); return err }, []byte("nameserver not-an-ip\n")},
		{"resolv unknown directive", func(b []byte) error { _, err := parseResolvConf(b, "wg0"); return err }, []byte("include /secret\n")},
		{"darwin no resolver", func(b []byte) error { _, err := parseDarwinDNS(b, "utun7"); return err }, []byte("nameserver[0] : 1.1.1.1\n")},
		{"windows bad continuation", func(b []byte) error { _, err := parseWindowsDNS(b, "wg0"); return err }, []byte("Unknown adapter wg0:\n DNS Servers : 1.1.1.1\n not-an-ip\n")},
		{"oversized", func(b []byte) error { _, err := parseDarwinDNS(b, "utun7"); return err }, bytes.Repeat([]byte("x"), maxCommandSize+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(tc.data); err == nil {
				t.Fatal("hostile DNS output accepted")
			}
		})
	}
}

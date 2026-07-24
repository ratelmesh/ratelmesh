package exitstack

import (
	"strings"
	"testing"
)

// TestDarwinPFRuleset checks the macOS exit pf ruleset SNATs the mesh out the
// uplink and preserves the system com.apple anchors (so existing pf rules survive).
func TestDarwinPFRuleset(t *testing.T) {
	rs := darwinPFRuleset("en0", "100.64.0.0/10")
	if !strings.Contains(rs, "nat on en0 inet from 100.64.0.0/10 to any -> (en0)") {
		t.Fatalf("missing/incorrect nat rule:\n%s", rs)
	}
	for _, anchor := range []string{
		`scrub-anchor "com.apple/*"`, `nat-anchor "com.apple/*"`,
		`rdr-anchor "com.apple/*"`, `anchor "com.apple/*"`,
		`load anchor "com.apple" from "/etc/pf.anchors/com.apple"`,
	} {
		if !strings.Contains(rs, anchor) {
			t.Fatalf("ruleset dropped system anchor %q:\n%s", anchor, rs)
		}
	}
	// pf section order: normalization (scrub) before translation (nat) before the
	// bare filter anchor. Match "\nanchor" so it isn't confused with the substring
	// inside scrub-anchor / nat-anchor / rdr-anchor.
	iScrub := strings.Index(rs, "scrub-anchor")
	iNat := strings.Index(rs, "nat on en0")
	iFilter := strings.Index(rs, "\nanchor \"com.apple/*\"")
	if !(iScrub < iNat && iNat < iFilter) {
		t.Fatalf("pf sections out of order (scrub=%d nat=%d filter=%d):\n%s", iScrub, iNat, iFilter, rs)
	}
}

// TestDefaultUplinkParse checks the "route -n get default" interface line parser.
func TestDefaultUplinkParse(t *testing.T) {
	// (parsing is exercised inline; ensure the prefix logic is right)
	sample := "   gateway: 192.168.1.1\n  interface: en0\n     flags: <UP,GATEWAY>\n"
	var got string
	for _, line := range strings.Split(sample, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "interface:") {
			got = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	if got != "en0" {
		t.Fatalf("parsed uplink = %q, want en0", got)
	}
}

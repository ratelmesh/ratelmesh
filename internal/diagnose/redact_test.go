package diagnose

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestRedactorDeterministic(t *testing.T) {
	in := "connect to https://user:secret@host.example.net/p?token=abc12345 from 203.0.113.9"
	r1 := NewRedactor([]byte("salt-A"), "supersecretvalue")
	r2 := NewRedactor([]byte("salt-A"), "supersecretvalue")
	if r1.String(in) != r2.String(in) {
		t.Fatal("same salt must produce identical redaction")
	}
	r3 := NewRedactor([]byte("salt-B"), "supersecretvalue")
	if r1.String(in) == r3.String(in) {
		t.Fatal("different salts should not produce identical fingerprints")
	}
}

func TestRedactorIdempotent(t *testing.T) {
	in := "key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= at 10.0.0.5 and de:ad:be:ef:00:11"
	r := NewRedactor([]byte("salt"))
	once := r.String(in)
	twice := r.String(once)
	if once != twice {
		t.Fatalf("redaction must be idempotent on its own output:\n once=%q\ntwice=%q", once, twice)
	}
}

func TestRedactorKnownSecret(t *testing.T) {
	secret := "rm-authkey-9f8e7d6c5b4a3210"
	r := NewRedactor([]byte("salt"), secret)
	out := r.String("the enrollment used " + secret + " to register")
	if strings.Contains(out, secret) {
		t.Fatalf("known secret leaked: %q", out)
	}
	if !strings.Contains(out, "[redacted:secret:") {
		t.Fatalf("expected a secret placeholder, got %q", out)
	}
}

func TestRedactorShortKnownSecretRedacted(t *testing.T) {
	// The no-secret guarantee must cover every non-empty registered secret, even
	// a short PIN or token. Over-redacting ordinary words is preferred to leaking
	// a registered secret, so short literals are scrubbed, not silently ignored.
	for _, secret := range []string{"a", "ab", "abc", "1234", "pin42"} {
		r := NewRedactor([]byte("salt"), secret)
		out := r.String("value " + secret + " end")
		if strings.Contains(out, " "+secret+" ") {
			t.Errorf("short secret %q leaked in value position: %q", secret, out)
		}
		if !strings.Contains(out, "[redacted:secret:") {
			t.Errorf("short secret %q should become a secret placeholder, got %q", secret, out)
		}
	}
}

func TestRedactorShortKnownSecretRedactedInKeys(t *testing.T) {
	// A short secret used as a JSON object key must be scrubbed too.
	secret := "pin"
	r := NewRedactor([]byte("salt"), secret)
	raw, err := json.Marshal(map[string]any{secret: "v", "other": "w"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.RedactJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, `"`+secret+`"`) {
		t.Errorf("short secret key %q leaked: %q", secret, s)
	}
	// Both values must survive even though a key was rewritten.
	for _, v := range []string{`"v"`, `"w"`} {
		if !strings.Contains(s, v) {
			t.Errorf("value %s dropped when a short-secret key was redacted: %q", v, s)
		}
	}
}

func TestRedactorEmptySecretIgnored(t *testing.T) {
	// An empty registered secret carries nothing to scrub and must not disturb
	// output (an empty-string replacer target would be meaningless).
	r := NewRedactor([]byte("salt"), "")
	in := "the coordinator is reachable"
	if got := r.String(in); got != in {
		t.Fatalf("empty secret must be ignored, got %q", got)
	}
}

func TestRedactorPatterns(t *testing.T) {
	r := NewRedactor([]byte("salt"))
	cases := []struct {
		name       string
		in         string
		mustAbsent []string
		mustHave   []string
	}{
		{
			name:       "jwt",
			in:         "auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlZGF0YQ token",
			mustAbsent: []string{"eyJhbGciOiJIUzI1NiJ9", "c2lnbmF0dXJlZGF0YQ"},
			mustHave:   []string{"[redacted:token:"},
		},
		{
			name:       "bearer",
			in:         "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123",
			mustAbsent: []string{"abcdefghijklmnopqrstuvwxyz0123"},
			mustHave:   []string{"Bearer [redacted:token:"},
		},
		{
			name: "url",
			in:   "GET https://alice:pw123456@coord.example.net:8443/status?token=zzz9&u=1#frag now",
			// The path must not survive: a token can live in a path segment.
			mustAbsent: []string{"coord.example.net", "pw123456", "token=zzz9", "alice:pw", "/status"},
			mustHave:   []string{"https://", ":8443", "[redacted:path:", "[redacted:query:", "[redacted:host:"},
		},
		{
			name:       "url token in path segment",
			in:         "onboard at https://coord.example.net/enroll/rm-authkey-9f8e7d6c5b4a done",
			mustAbsent: []string{"rm-authkey-9f8e7d6c5b4a", "/enroll/"},
			mustHave:   []string{"https://", "[redacted:path:", "[redacted:host:"},
		},
		{
			name:       "email",
			in:         "contact songling@example.com please",
			mustAbsent: []string{"songling@example.com"},
			mustHave:   []string{"[redacted:email:"},
		},
		{
			name:       "unix home path",
			in:         "log at /Users/songling/Library/rm/state.json today",
			mustAbsent: []string{"/Users/songling/"},
			mustHave:   []string{"/Users/[redacted:user:", "/Library/rm/state.json"},
		},
		{
			name:       "windows home path",
			in:         `file C:\Users\songling\AppData\rm.log`,
			mustAbsent: []string{`C:\Users\songling\`},
			mustHave:   []string{"[redacted:user:"},
		},
		{
			name:       "wireguard key",
			in:         "peer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= up",
			mustAbsent: []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
			mustHave:   []string{"[redacted:key:"},
		},
		{
			name:       "hex key",
			in:         "id 0123456789abcdef0123456789abcdef done",
			mustAbsent: []string{"0123456789abcdef0123456789abcdef"},
			mustHave:   []string{"[redacted:key:"},
		},
		{
			name:       "mac",
			in:         "hw de:ad:be:ef:00:11 seen",
			mustAbsent: []string{"de:ad:be:ef:00:11"},
			mustHave:   []string{"[redacted:mac:"},
		},
		{
			name:       "ipv4 classes",
			in:         "public 8.8.4.4 private 192.168.1.7 mesh 100.64.0.3 loopback 127.0.0.1",
			mustAbsent: []string{"8.8.4.4", "192.168.1.7", "100.64.0.3", "127.0.0.1"},
			mustHave:   []string{"[redacted:ip-public:", "[redacted:ip-private:", "[redacted:ip-mesh:", "[redacted:ip-loopback:"},
		},
		{
			name:       "ipv6",
			in:         "v6 2001:4860:4860::8888 link fe80::1",
			mustAbsent: []string{"2001:4860:4860::8888"},
			mustHave:   []string{"[redacted:ip-public:", "[redacted:ip-linklocal:"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := r.String(tc.in)
			for _, a := range tc.mustAbsent {
				if strings.Contains(out, a) {
					t.Errorf("expected %q to be absent, got %q", a, out)
				}
			}
			for _, h := range tc.mustHave {
				if !strings.Contains(out, h) {
					t.Errorf("expected %q to be present, got %q", h, out)
				}
			}
		})
	}
}

func TestRedactorLeavesProseAlone(t *testing.T) {
	r := NewRedactor([]byte("salt"))
	in := "the coordinator is reachable and the exit is healthy"
	if got := r.String(in); got != in {
		t.Fatalf("prose should be untouched, got %q", got)
	}
}

func TestClassifyIP(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1":         "loopback",
		"0.0.0.0":           "unspecified",
		"169.254.1.1":       "linklocal",
		"100.64.0.3":        "mesh",
		"10.1.2.3":          "private",
		"192.168.0.1":       "private",
		"8.8.8.8":           "public",
		"fe80::1":           "linklocal",
		"fc00::1":           "private",
		"2606:4700:4700::1": "public",
	}
	for in, want := range cases {
		if got := classifyIP(netip.MustParseAddr(in)); got != want {
			t.Errorf("classifyIP(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactJSONTree(t *testing.T) {
	doc := map[string]any{
		"code": "dns.timeout",
		"nested": map[string]any{
			"ip":    "192.168.1.9",
			"count": 3,
		},
		"list": []any{"pw@host.example.net", "plain-text"},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	r := NewRedactor([]byte("salt"))
	out, err := r.RedactJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, absent := range []string{"192.168.1.9", "host.example.net"} {
		if strings.Contains(s, absent) {
			t.Errorf("%q leaked into %q", absent, s)
		}
	}
	for _, present := range []string{`"count":3`, "dns.timeout", "plain-text", "ip-private"} {
		if !strings.Contains(s, present) {
			t.Errorf("expected %q preserved in %q", present, s)
		}
	}
}

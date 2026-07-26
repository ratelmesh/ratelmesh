package diagnose

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Redactor deterministically removes sensitive data from free text so a support
// report can be shared safely. It works two ways, both applied by String:
//
//  1. Known-secret substitution. Literals registered at construction (auth keys,
//     tokens, private-key material, host names) are replaced wherever they
//     appear, giving an airtight guarantee for values the daemon knows are
//     sensitive.
//  2. Structural pattern scrubbing. A fixed battery of patterns catches secrets
//     and identifiers the caller did not register: private-key blocks, JWTs,
//     bearer credentials, URLs (userinfo, host, query, fragment), e-mail
//     addresses, home-directory paths, WireGuard/base64/hex keys, MAC and IP
//     addresses.
//
// Redaction is deterministic: a value always maps to the same placeholder given
// the same salt, so equal secrets stay correlatable within a report while
// remaining unrecoverable. Production uses a fresh random salt per report (so
// fingerprints cannot be correlated or brute-forced across reports); tests fix
// the salt for byte-stable output.
//
// If a Redactor is sealed (see newSealedRedactor), it emits opaque, value-free
// placeholders that carry no fingerprint at all. That mode is the fail-closed
// fallback used when the process cannot obtain cryptographic entropy for a fresh
// per-report salt: rather than emit predictable, dictionary-verifiable HMAC
// fingerprints (which a constant or guessable salt would produce), a sealed
// Redactor over-redacts — every value of a kind collapses to the same marker, so
// nothing leaks and nothing correlates across reports.
type Redactor struct {
	salt          []byte
	knownReplacer *strings.Replacer // simultaneous, non-overlapping literal scrub
	// sealed drops all value-derived fingerprints in favour of opaque markers.
	sealed bool
}

// NewRedactor returns a Redactor with the given salt (which may be nil) and set
// of known secret literals. Duplicate and empty literals are ignored; every
// other non-empty registered secret is scrubbed wherever it appears — including
// very short PIN- or token-sized values. A short literal can over-redact
// ordinary words, but the no-secret guarantee must cover every registered
// secret, so over-redaction is preferred to a silent leak.
func NewRedactor(salt []byte, knownSecrets ...string) *Redactor {
	r := &Redactor{salt: append([]byte(nil), salt...)}
	r.buildKnownReplacer(knownSecrets)
	return r
}

// newSealedRedactor returns a Redactor that emits opaque, non-fingerprinting
// placeholders. It is the fail-closed path taken when crypto/rand cannot seed a
// fresh salt: it still scrubs every known secret and every recognised pattern,
// but never emits an HMAC fingerprint that a constant/guessable salt would make
// predictable and dictionary-verifiable.
func newSealedRedactor(knownSecrets ...string) *Redactor {
	r := &Redactor{sealed: true}
	r.buildKnownReplacer(knownSecrets)
	return r
}

func (r *Redactor) buildKnownReplacer(secrets []string) {
	seen := make(map[string]bool)
	uniq := make([]string, 0, len(secrets))
	for _, s := range secrets {
		// Empty strings carry nothing to scrub; everything else — however short —
		// must be redacted. A registered PIN or short token would otherwise survive
		// verbatim, which is exactly the leak this guarantees against.
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		uniq = append(uniq, s)
	}
	if len(uniq) == 0 {
		return
	}
	// Longest-first so a secret that contains another is replaced whole.
	sort.Slice(uniq, func(i, j int) bool {
		if len(uniq[i]) != len(uniq[j]) {
			return len(uniq[i]) > len(uniq[j])
		}
		return uniq[i] < uniq[j]
	})
	pairs := make([]string, 0, len(uniq)*2)
	for _, s := range uniq {
		pairs = append(pairs, s, r.tag("secret", s))
	}
	r.knownReplacer = strings.NewReplacer(pairs...)
}

// tag renders the redaction marker for a value of the given kind. In the normal
// (salted) mode it embeds a per-value HMAC fingerprint so equal values stay
// correlatable within a report. In sealed mode it drops the fingerprint entirely
// and returns an opaque, value-free marker, so a report produced without trusted
// entropy leaks neither the raw value nor a predictable fingerprint an attacker
// could dictionary-verify or correlate across reports.
func (r *Redactor) tag(kind, v string) string {
	if r.sealed {
		return sealedPlaceholder(kind)
	}
	return placeholder(kind, r.fingerprint(kind, v))
}

// tokenIdentifier turns one already-classified identifier into a deterministic
// opaque token without registering it for global substring replacement. This
// matters for arbitrary interface names: a valid one-character name must not
// survive, but registering "a" as a known secret would destroy every unrelated
// word containing that letter.
func (r *Redactor) tokenIdentifier(kind, value string) string {
	if value == "" {
		return ""
	}
	if r == nil {
		return sealedPlaceholder(kind)
	}
	return r.tag(kind, value)
}

// fingerprint returns a short, non-reversible tag for a value under the current
// salt. Twelve hex characters (48 bits) is enough to keep equal values
// correlatable without acting as a recoverable encoding.
func (r *Redactor) fingerprint(kind, v string) string {
	mac := hmac.New(sha256.New, r.salt)
	mac.Write([]byte(kind))
	mac.Write([]byte{0})
	mac.Write([]byte(v))
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum[:6])
}

// placeholder renders the stable redaction marker. The form is ASCII and
// contains no run that any scrubbing pattern can match, so placeholders are
// never re-redacted.
func placeholder(kind, fp string) string {
	return "[redacted:" + kind + ":" + fp + "]"
}

// sealedPlaceholder renders the opaque, fingerprint-free marker used in sealed
// mode. It carries only the coarse kind, never any value-derived data, so it
// cannot be dictionary-verified or used to correlate a value across reports.
func sealedPlaceholder(kind string) string {
	return "[redacted:" + kind + "]"
}

// String returns s with every known secret and recognised sensitive pattern
// replaced by a deterministic placeholder.
func (r *Redactor) String(s string) string {
	if s == "" {
		return s
	}
	if r.knownReplacer != nil {
		s = r.knownReplacer.Replace(s)
	}
	return r.scrubPatterns(s)
}

// RedactJSON walks an arbitrary JSON document and redacts every string value and
// every object key, leaving structure and numbers intact. Numbers are decoded
// with UseNumber so they round-trip exactly. It is the final, guaranteed scrub
// the report applies before emitting bytes.
func (r *Redactor) RedactJSON(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	return json.Marshal(r.redactTree(tree))
}

func (r *Redactor) redactTree(v any) any {
	switch t := v.(type) {
	case string:
		return r.String(t)
	case []any:
		for i := range t {
			t[i] = r.redactTree(t[i])
		}
		return t
	case map[string]any:
		// Keys are redacted too: a secret (auth key, host, token) can appear in a
		// key just as easily as in a value. Two distinct keys can redact to the
		// same string (for example a real host and a client-supplied key that
		// mimics that host's placeholder); handling that deterministically is
		// essential so one value cannot silently overwrite another. Process keys
		// in sorted original order (independent of Go's random map iteration) and
		// disambiguate any collision with a non-reversible, per-key suffix.
		out := make(map[string]any, len(t))
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			rk := r.String(k)
			if _, taken := out[rk]; taken {
				rk = r.disambiguateKey(out, rk, k)
			}
			out[rk] = r.redactTree(t[k])
		}
		return out
	default:
		// numbers (json.Number), bools and nil pass through untouched.
		return v
	}
}

// disambiguateKey returns a redacted key that does not collide with any key
// already in out. In salted mode it appends a non-reversible suffix derived from
// the original key (an HMAC fingerprint, so the raw key never leaks); in sealed
// mode — where no value-derived fingerprint may be emitted — it relies solely on
// an incrementing numeric tail. Either way the result is deterministic given the
// sorted key-insertion order, so no value is ever silently overwritten and the
// output stays stable.
func (r *Redactor) disambiguateKey(out map[string]any, base, orig string) string {
	suffix := ""
	if !r.sealed {
		suffix = "#" + r.fingerprint("key", orig)
	}
	cand := base + suffix
	for n := 2; ; n++ {
		if _, taken := out[cand]; !taken {
			return cand
		}
		cand = base + suffix + "#" + strconv.Itoa(n)
	}
}

// Compiled scrubbing patterns, applied in the fixed order used by scrubPatterns.
var (
	rePEM                 = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	reJWT                 = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b`)
	reBearer              = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}`)
	reURL                 = regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s"'<>` + "`" + `]+`)
	reEmail               = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	rePath                = regexp.MustCompile(`(?i)(/users/|/home/|[a-z]:\\users\\|\\users\\)([^/\\\s:"']+)`)
	reUnixAbsolutePath    = regexp.MustCompile(`(^|[\s("'=])(/[^\s"'<>` + "`" + `]+)`)
	reWindowsAbsolutePath = regexp.MustCompile(`(?i)(^|[\s("'=])((?:[a-z]:\\|\\\\)[^\s"'<>` + "`" + `]+)`)
	reWGKey               = regexp.MustCompile(`\b[A-Za-z0-9+/]{43}=`)
	reB64                 = regexp.MustCompile(`\b[A-Za-z0-9+/]{40,}={0,2}`)
	reHex                 = regexp.MustCompile(`\b[0-9a-fA-F]{32,}\b`)
	reMAC                 = regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b`)
	reIPv4                = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
)

// urlTrailing is the set of punctuation trimmed from a URL match before parsing
// so trailing prose punctuation is not swallowed into the URL.
const urlTrailing = ".,;:!?)]}'\""

func (r *Redactor) scrubPatterns(s string) string {
	s = rePEM.ReplaceAllStringFunc(s, func(m string) string { return r.tag("key", m) })
	s = reJWT.ReplaceAllStringFunc(s, func(m string) string { return r.tag("token", m) })
	s = reBearer.ReplaceAllStringFunc(s, func(m string) string {
		i := strings.IndexAny(m, " \t")
		cred := strings.TrimSpace(m[i:])
		return m[:i] + " " + r.tag("token", cred)
	})
	s = reURL.ReplaceAllStringFunc(s, r.redactURL)
	s = reEmail.ReplaceAllStringFunc(s, func(m string) string { return r.tag("email", m) })
	s = rePath.ReplaceAllStringFunc(s, func(m string) string {
		sub := rePath.FindStringSubmatch(m)
		return sub[1] + r.tag("user", sub[2])
	})
	s = reUnixAbsolutePath.ReplaceAllStringFunc(s, func(m string) string {
		sub := reUnixAbsolutePath.FindStringSubmatch(m)
		return sub[1] + r.tag("path", sub[2])
	})
	s = reWindowsAbsolutePath.ReplaceAllStringFunc(s, func(m string) string {
		sub := reWindowsAbsolutePath.FindStringSubmatch(m)
		return sub[1] + r.tag("path", sub[2])
	})
	s = reWGKey.ReplaceAllStringFunc(s, func(m string) string { return r.tag("key", m) })
	s = reB64.ReplaceAllStringFunc(s, func(m string) string { return r.tag("key", m) })
	s = reHex.ReplaceAllStringFunc(s, func(m string) string { return r.tag("key", m) })
	s = reMAC.ReplaceAllStringFunc(s, func(m string) string { return r.tag("mac", m) })
	s = r.scrubIPv6(s)
	s = reIPv4.ReplaceAllStringFunc(s, r.redactIP)
	return s
}

// scrubIPv6 redacts IPv6 literals. A regex cannot reliably match the "::"
// compressed form without splitting an address, so instead it scans maximal
// runs of IPv6 characters and validates each run with netip: only a run that
// parses as a whole IPv6 address is redacted, so timestamps like "12:34:56" and
// hex fragments are left untouched.
func (r *Redactor) scrubIPv6(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if !isIPv6Char(s[i]) {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i
		for j < len(s) && isIPv6Char(s[j]) {
			j++
		}
		run := s[i:j]
		if a, err := netip.ParseAddr(run); err == nil && a.Is6() {
			b.WriteString(r.tag("ip-"+classifyIP(a), run))
		} else {
			b.WriteString(run)
		}
		i = j
	}
	return b.String()
}

// isIPv6Char reports whether c can appear in a colon-hex IPv6 literal.
func isIPv6Char(c byte) bool {
	switch {
	case c >= '0' && c <= '9':
		return true
	case c >= 'a' && c <= 'f':
		return true
	case c >= 'A' && c <= 'F':
		return true
	case c == ':':
		return true
	default:
		return false
	}
}

// redactIP validates a candidate dotted-quad and, if valid, replaces it with a
// placeholder that preserves its coarse class (loopback, linklocal, mesh,
// private, multicast or public) but not its value. Invalid candidates (for
// example "999.1.2.3") are left untouched.
func (r *Redactor) redactIP(m string) string {
	a, err := netip.ParseAddr(m)
	if err != nil {
		return m
	}
	return r.tag("ip-"+classifyIP(a), m)
}

// redactURL keeps the scheme and coarse host class of a URL while removing
// userinfo, the exact host, the query and the fragment. Trailing prose
// punctuation is preserved outside the placeholder.
func (r *Redactor) redactURL(raw string) string {
	trailing := ""
	for len(raw) > 0 {
		c := raw[len(raw)-1]
		if strings.IndexByte(urlTrailing, c) < 0 {
			break
		}
		trailing = string(c) + trailing
		raw = raw[:len(raw)-1]
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return r.tag("url", raw) + trailing
	}
	var b strings.Builder
	b.WriteString(u.Scheme)
	b.WriteString("://")
	if u.User != nil {
		b.WriteString(r.tag("secret", u.User.String()))
		b.WriteByte('@')
	}
	b.WriteString(r.redactHost(u.Hostname()))
	if p := u.Port(); p != "" {
		b.WriteByte(':')
		b.WriteString(p)
	}
	// The path must never survive raw: onboarding/API tokens routinely live in
	// path segments (for example /enroll/<authkey>). Replace the whole path with
	// a deterministic placeholder; a bare "/" carries no information and stays.
	if u.Path != "" && u.Path != "/" {
		b.WriteByte('/')
		b.WriteString(r.tag("path", u.Path))
	} else {
		b.WriteString(u.Path)
	}
	if u.RawQuery != "" {
		b.WriteString("?")
		b.WriteString(r.tag("query", u.RawQuery))
	}
	if u.Fragment != "" {
		b.WriteString("#")
		b.WriteString(r.tag("frag", u.Fragment))
	}
	return b.String() + trailing
}

// redactHost classifies a URL host: an IP literal keeps its coarse class, a
// name becomes an opaque host fingerprint.
func (r *Redactor) redactHost(host string) string {
	if a, err := netip.ParseAddr(host); err == nil {
		return r.tag("ip-"+classifyIP(a), host)
	}
	return r.tag("host", host)
}

// cgnatV4 is the 100.64.0.0/10 CGNAT range RatelMesh allocates mesh IPs from.
var cgnatV4 = netip.MustParsePrefix("100.64.0.0/10")

// classifyIP maps an address to a coarse, non-identifying class.
func classifyIP(a netip.Addr) string {
	switch {
	case a.IsLoopback():
		return "loopback"
	case a.IsUnspecified():
		return "unspecified"
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		return "linklocal"
	case a.Is4() && cgnatV4.Contains(a):
		return "mesh"
	case a.IsPrivate():
		return "private"
	case a.IsMulticast():
		return "multicast"
	default:
		return "public"
	}
}

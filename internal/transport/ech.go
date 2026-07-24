package transport

// Encrypted ClientHello (ECH) support for the WSS transport: fetch the target's
// ECHConfigList from its DNS HTTPS record and hand it to crypto/tls, which then
// encrypts the inner ClientHello — so the real SNI (which domain we connect to)
// never appears in cleartext on the wire, only a CDN decoy name. This closes the
// last plaintext identifier left after moving the relay onto TLS (§8).

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// fetchECHConfigList retrieves the ECHConfigList (SvcParam key 5) from host's DNS
// HTTPS record via Cloudflare DoH-over-HTTPS. The DoH request's own SNI is
// cloudflare-dns.com — a ubiquitous name — so bootstrapping ECH does not itself
// leak the target. Best effort: returns nil on any error, and the caller falls
// back to a normal (plaintext-SNI) TLS handshake.
func fetchECHConfigList(ctx context.Context, host string) []byte {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	u := "https://cloudflare-dns.com/dns-query?type=HTTPS&name=" + url.QueryEscape(host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("accept", "application/dns-json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var body struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil
	}
	for _, a := range body.Answer {
		if a.Type != 65 { // HTTPS RR
			continue
		}
		if ech := echFromSVCB(parseGenericRDATA(a.Data)); len(ech) > 0 {
			return ech
		}
	}
	return nil
}

// parseGenericRDATA decodes RFC 3597 generic RR presentation: `\# <len> <hex…>`.
func parseGenericRDATA(s string) []byte {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, `\#`) {
		return nil
	}
	f := strings.Fields(s)
	if len(f) < 3 {
		return nil
	}
	b, err := hex.DecodeString(strings.Join(f[2:], ""))
	if err != nil {
		return nil
	}
	return b
}

// echFromSVCB extracts SvcParam key 5 (ech) from an SVCB/HTTPS RDATA:
// 2-byte SvcPriority, an uncompressed TargetName, then key(2)/len(2)/value SvcParams.
func echFromSVCB(r []byte) []byte {
	if len(r) < 3 {
		return nil
	}
	i := 2           // skip SvcPriority
	for i < len(r) { // skip TargetName labels (terminated by 0x00)
		l := int(r[i])
		i++
		if l == 0 {
			break
		}
		i += l
	}
	for i+4 <= len(r) {
		key := int(r[i])<<8 | int(r[i+1])
		ln := int(r[i+2])<<8 | int(r[i+3])
		i += 4
		if i+ln > len(r) {
			break
		}
		if key == 5 { // ech
			return append([]byte(nil), r[i:i+ln]...)
		}
		i += ln
	}
	return nil
}

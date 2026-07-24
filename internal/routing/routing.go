// Package routing is RatelMesh's split-tunnel decision engine (DESIGN.md §8.4).
// For each destination it decides whether traffic goes direct (out the local
// ISP), through the tunnel/exit, or is blocked — the mechanism behind "domestic
// traffic direct, censored traffic via exit". Rules cover exact domains, domain
// suffixes, IP CIDRs, and GeoIP country sets; the ruleset is hot-updatable.
package routing

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Action is the routing decision for a destination.
type Action string

const (
	ActionDirect Action = "direct" // bypass the tunnel, use the local network
	ActionTunnel Action = "tunnel" // send through the mesh/exit
	ActionBlock  Action = "block"  // drop (e.g. ads/malware)
)

// ruleDoc is the JSON form of a ruleset.
type ruleDoc struct {
	Default Action     `json:"default"`
	Rules   []ruleItem `json:"rules"`
}

type ruleItem struct {
	Domains  []string            `json:"domains"`  // exact domain matches
	Suffixes []string            `json:"suffixes"` // domain suffix matches
	CIDRs    []string            `json:"cidrs"`    // IP prefix matches
	GeoIP    map[string][]string `json:"geoip"`    // country code -> CIDRs
	Action   Action              `json:"action"`
}

// Engine evaluates routing rules. It is safe for concurrent reads.
type Engine struct {
	exact    map[string]Action
	suffixes []suffixRule
	cidrs    []cidrRule
	def      Action
}

type suffixRule struct {
	suffix string
	action Action
}

type cidrRule struct {
	prefix netip.Prefix
	action Action
}

// Parse builds an Engine from a JSON ruleset.
func Parse(data []byte) (*Engine, error) {
	var doc ruleDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("routing: parse: %w", err)
	}
	return build(doc)
}

// Default returns an engine that tunnels everything (no split-tunnel).
func Default() *Engine {
	return &Engine{exact: map[string]Action{}, def: ActionTunnel}
}

func build(doc ruleDoc) (*Engine, error) {
	e := &Engine{exact: map[string]Action{}, def: doc.Default}
	if e.def == "" {
		e.def = ActionTunnel
	}
	for i, r := range doc.Rules {
		if !validAction(r.Action) {
			return nil, fmt.Errorf("routing: rule %d: invalid action %q", i, r.Action)
		}
		for _, d := range r.Domains {
			e.exact[normalizeHost(d)] = r.Action
		}
		for _, s := range r.Suffixes {
			e.suffixes = append(e.suffixes, suffixRule{normalizeHost(s), r.Action})
		}
		for _, c := range r.CIDRs {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return nil, fmt.Errorf("routing: rule %d: bad cidr %q: %w", i, c, err)
			}
			e.cidrs = append(e.cidrs, cidrRule{p, r.Action})
		}
		for _, cidrs := range r.GeoIP {
			for _, c := range cidrs {
				p, err := netip.ParsePrefix(c)
				if err != nil {
					return nil, fmt.Errorf("routing: rule %d: bad geoip cidr %q: %w", i, c, err)
				}
				e.cidrs = append(e.cidrs, cidrRule{p, r.Action})
			}
		}
	}
	// Longest suffix first so the most specific domain rule wins.
	sort.Slice(e.suffixes, func(i, j int) bool {
		return len(e.suffixes[i].suffix) > len(e.suffixes[j].suffix)
	})
	// Longest prefix first for most-specific IP match.
	sort.Slice(e.cidrs, func(i, j int) bool {
		return e.cidrs[i].prefix.Bits() > e.cidrs[j].prefix.Bits()
	})
	return e, nil
}

// Decide routes a destination given as a hostname or IP literal (optionally with
// a port, which is ignored).
func (e *Engine) Decide(host string) Action {
	h := stripPort(host)
	if addr, err := netip.ParseAddr(h); err == nil {
		return e.DecideIP(addr)
	}
	return e.DecideDomain(h)
}

// DecideDomain routes a domain name.
func (e *Engine) DecideDomain(name string) Action {
	name = normalizeHost(name)
	if a, ok := e.exact[name]; ok {
		return a
	}
	for _, s := range e.suffixes {
		if name == s.suffix || strings.HasSuffix(name, "."+s.suffix) {
			return s.action
		}
	}
	return e.def
}

// DecideIP routes an IP address via longest-prefix match.
func (e *Engine) DecideIP(addr netip.Addr) Action {
	for _, c := range e.cidrs { // already sorted longest-prefix first
		if c.prefix.Contains(addr) {
			return c.action
		}
	}
	return e.def
}

// DirectPrefixes returns the CIDRs the ruleset routes directly (bypassing the
// tunnel), e.g. GeoIP "domestic" ranges. These become physical-gateway routes
// that override the exit's default route (DESIGN.md §8.4). Domain-based rules
// are not included — they require DNS-time decisions, not static routes.
func (e *Engine) DirectPrefixes() []netip.Prefix { return e.prefixesFor(ActionDirect) }

// BlockPrefixes returns the CIDRs the ruleset drops (blackhole routes).
func (e *Engine) BlockPrefixes() []netip.Prefix { return e.prefixesFor(ActionBlock) }

func (e *Engine) prefixesFor(a Action) []netip.Prefix {
	var out []netip.Prefix
	for _, c := range e.cidrs {
		if c.action == a {
			out = append(out, c.prefix)
		}
	}
	return out
}

func validAction(a Action) bool {
	return a == ActionDirect || a == ActionTunnel || a == ActionBlock
}

func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

func stripPort(host string) string {
	// Handle "host:port" and "[v6]:port" without importing net for the fast path.
	if strings.HasPrefix(host, "[") {
		if i := strings.LastIndex(host, "]"); i >= 0 {
			return host[1:i]
		}
	}
	if i := strings.LastIndex(host, ":"); i >= 0 {
		// Only treat as port if the remainder is all digits (avoid splitting v6).
		if isPort(host[i+1:]) && strings.Count(host, ":") == 1 {
			return host[:i]
		}
	}
	return host
}

func isPort(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

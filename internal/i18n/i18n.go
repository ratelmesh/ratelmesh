// Package i18n is RatelMesh's localization runtime (DESIGN.md §9). Message
// catalogs (one JSON per locale, the single source of truth under
// internal/i18n/locales) are embedded at build time. Lookups fall back
// locale -> base language -> English, and a missing key returns the key itself
// rather than erroring. Patterns use an ICU-subset: named placeholders {name}
// and plurals {count, plural, one {# x} other {# xs}}.
package i18n

import (
	"embed"
	"encoding/json"
	"sort"
	"strings"
	"sync"
)

//go:embed locales/*.json
var catalogFS embed.FS

// Bundle holds all loaded catalogs and resolves messages for a locale.
type Bundle struct {
	mu       sync.RWMutex
	catalogs map[string]map[string]string // locale code -> key -> pattern
}

// defaultBundle is the process-wide bundle loaded from embedded catalogs.
var defaultBundle = mustLoad()

func mustLoad() *Bundle {
	b := &Bundle{catalogs: map[string]map[string]string{}}
	entries, _ := catalogFS.ReadDir("locales")
	for _, e := range entries {
		data, err := catalogFS.ReadFile("locales/" + e.Name())
		if err != nil {
			continue
		}
		var raw map[string]json.RawMessage
		if json.Unmarshal(data, &raw) != nil {
			continue
		}
		code := strings.TrimSuffix(e.Name(), ".json")
		cat := map[string]string{}
		for k, v := range raw {
			if k == "_meta" {
				continue
			}
			var s string
			if json.Unmarshal(v, &s) == nil {
				cat[k] = s
			}
		}
		b.catalogs[code] = cat
	}
	return b
}

// Available returns the loaded locale codes.
func Available() []string {
	defaultBundle.mu.RLock()
	defer defaultBundle.mu.RUnlock()
	out := make([]string, 0, len(defaultBundle.catalogs))
	for code := range defaultBundle.catalogs {
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}

// Printer localizes messages for one locale, with fallback.
type Printer struct {
	locale string
	chain  []string // resolution order, e.g. ["zh-Hant","zh","en"]
}

// NewPrinter builds a Printer for a locale tag (e.g. "zh-Hans", "en-US"). The
// resolution chain is the exact tag, its base language, then English.
func NewPrinter(locale string) *Printer {
	locale = normalizeTag(locale)
	chain := []string{locale}
	// POSIX/Linux commonly reports Simplified Chinese as zh_CN.UTF-8, while
	// the shipped BCP-47 catalog is zh-Hans. Bridge the equivalent tags so a
	// Chinese system never unexpectedly falls back to English.
	switch {
	case locale == "zh", locale == "zh-CN", locale == "zh-SG", strings.HasPrefix(locale, "zh-Hans-"):
		chain = append(chain, "zh-Hans")
	case locale == "zh-TW", locale == "zh-HK", locale == "zh-MO", strings.HasPrefix(locale, "zh-Hant-"):
		chain = append(chain, "zh-Hant")
	}
	if base := baseLang(locale); base != locale {
		chain = append(chain, base)
	}
	if locale != "en" {
		chain = append(chain, "en")
	}
	return &Printer{locale: locale, chain: chain}
}

// Locale returns the printer's primary locale.
func (p *Printer) Locale() string { return p.locale }

// T localizes key, expanding {placeholders} and plurals from args. Unknown keys
// return the key itself (visible but non-fatal, DESIGN.md §9.3).
func (p *Printer) T(key string, args ...Arg) string {
	pattern, ok := p.lookup(key)
	if !ok {
		return key
	}
	m := make(map[string]any, len(args))
	for _, a := range args {
		m[a.Name] = a.Value
	}
	return expand(pattern, m, pluralLang(p.locale))
}

func (p *Printer) lookup(key string) (string, bool) {
	defaultBundle.mu.RLock()
	defer defaultBundle.mu.RUnlock()
	for _, code := range p.chain {
		if cat, ok := defaultBundle.catalogs[code]; ok {
			if pat, ok := cat[key]; ok {
				return pat, true
			}
		}
	}
	return "", false
}

// Arg is a named argument to T.
type Arg struct {
	Name  string
	Value any
}

// V is a shorthand constructor for an Arg.
func V(name string, value any) Arg { return Arg{Name: name, Value: value} }

func normalizeTag(tag string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return "en"
	}
	// Strip encoding/modifier suffixes from POSIX locales: zh_CN.UTF-8 -> zh-CN.
	if i := strings.IndexAny(tag, ".@"); i >= 0 {
		tag = tag[:i]
	}
	parts := strings.Split(strings.ReplaceAll(tag, "_", "-"), "-")
	parts[0] = strings.ToLower(parts[0])
	for i := 1; i < len(parts); i++ {
		p := strings.ToLower(parts[i])
		switch len(p) {
		case 2, 3: // ISO region (or numeric UN M49 region)
			parts[i] = strings.ToUpper(p)
		case 4: // script, e.g. Hans/Hant
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		default:
			parts[i] = p
		}
	}
	return strings.Join(parts, "-")
}

func baseLang(tag string) string {
	if i := strings.Index(tag, "-"); i >= 0 {
		return tag[:i]
	}
	return tag
}

// pluralLang maps a locale to its plural rule family.
func pluralLang(locale string) string { return baseLang(locale) }

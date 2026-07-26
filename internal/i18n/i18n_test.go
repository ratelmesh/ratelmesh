package i18n

import "testing"

func TestSimplePlaceholder(t *testing.T) {
	p := NewPrinter("en")
	got := p.T("status.dns", V("resolver", "https://dns.ratelmesh"))
	want := "DNS:     https://dns.ratelmesh"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPluralEnglish(t *testing.T) {
	p := NewPrinter("en")
	if got := p.T("status.netmap", V("version", 3), V("count", 1)); got != "Netmap:  v3, 1 peer" {
		t.Errorf("singular: %q", got)
	}
	if got := p.T("status.netmap", V("version", 3), V("count", 5)); got != "Netmap:  v3, 5 peers" {
		t.Errorf("plural: %q", got)
	}
}

func TestChinesePluralHasNoSingular(t *testing.T) {
	p := NewPrinter("zh-Hans")
	one := p.T("status.netmap", V("version", 1), V("count", 1))
	many := p.T("status.netmap", V("version", 1), V("count", 9))
	if one != "网络图： v1，1 个对端" {
		t.Errorf("zh one: %q", one)
	}
	if many != "网络图： v1，9 个对端" {
		t.Errorf("zh many: %q", many)
	}
}

func TestFallbackToEnglish(t *testing.T) {
	// A locale with no catalog falls back to English.
	p := NewPrinter("xx-YY")
	if got := p.T("status.nopeers"); got != "No peers yet." {
		t.Errorf("fallback: %q", got)
	}
}

func TestBaseLanguageFallback(t *testing.T) {
	p := NewPrinter("zh-CN")
	if p.Locale() != "zh-CN" {
		t.Errorf("locale = %q", p.Locale())
	}
	if got := p.T("exit.cleared"); got != "已恢复直连出网（未使用出口）。" {
		t.Errorf("zh exit.cleared: %q", got)
	}
}

func TestTraditionalChineseRegionFallback(t *testing.T) {
	p := NewPrinter("zh_TW.UTF-8")
	if got := p.T("exit.cleared"); got != "已恢復直接連線（未使用出口節點）。" {
		t.Errorf("zh-TW exit.cleared: %q", got)
	}
}

func TestUnknownKeyReturnsKey(t *testing.T) {
	p := NewPrinter("en")
	if got := p.T("no.such.key"); got != "no.such.key" {
		t.Errorf("unknown key: %q", got)
	}
}

func TestPOSIXLocaleNormalization(t *testing.T) {
	p := NewPrinter("zh_CN.UTF-8")
	if got := p.T("status.nopeers"); got != "暂无对端。" {
		t.Errorf("posix simplified-Chinese mapping: %q", got)
	}
	// Locale tags are case-insensitive; normalize script/region casing too.
	if got := NewPrinter("JA_jp.UTF-8").T("status.nopeers"); got != "ピアはまだありません。" {
		t.Errorf("case-insensitive Japanese locale: %q", got)
	}
}

func TestAvailableIncludesShippedLocales(t *testing.T) {
	got := map[string]bool{}
	for _, c := range Available() {
		got[c] = true
	}
	for _, want := range []string{"en", "es", "de", "fr", "ja", "ko", "it", "nl", "pl", "sv", "pt-BR", "zh-Hans", "zh-Hant"} {
		if !got[want] {
			t.Errorf("missing locale %q in %v", want, Available())
		}
	}
}

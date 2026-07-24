package routing

import (
	"net/netip"
	"testing"
)

const sample = `{
  "default": "tunnel",
  "rules": [
    {"domains": ["ads.tracker.com"], "action": "block"},
    {"suffixes": ["cn", "baidu.com", "qq.com"], "action": "direct"},
    {"suffixes": ["google.com"], "action": "tunnel"},
    {"cidrs": ["10.0.0.0/8", "192.168.0.0/16"], "action": "direct"},
    {"geoip": {"cn": ["1.2.4.0/24"]}, "action": "direct"}
  ]
}`

func mustEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestDomainDecisions(t *testing.T) {
	e := mustEngine(t)
	cases := map[string]Action{
		"www.baidu.com":   ActionDirect, // suffix baidu.com
		"baidu.com":       ActionDirect, // exact-as-suffix
		"map.qq.com":      ActionDirect,
		"weibo.cn":        ActionDirect, // suffix cn
		"mail.google.com": ActionTunnel, // suffix google.com
		"ads.tracker.com": ActionBlock,  // exact
		"example.org":     ActionTunnel, // default
	}
	for host, want := range cases {
		if got := e.Decide(host); got != want {
			t.Errorf("Decide(%q) = %s, want %s", host, got, want)
		}
	}
}

func TestSuffixSpecificityWins(t *testing.T) {
	// "google.com" -> tunnel must win over the broader "com"? There is no "com"
	// rule, but ensure longer suffix beats shorter when both match.
	e, err := Parse([]byte(`{"default":"tunnel","rules":[
		{"suffixes":["com"],"action":"direct"},
		{"suffixes":["google.com"],"action":"tunnel"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := e.DecideDomain("mail.google.com"); got != ActionTunnel {
		t.Errorf("longer suffix should win: got %s", got)
	}
	if got := e.DecideDomain("example.com"); got != ActionDirect {
		t.Errorf("shorter suffix fallback: got %s", got)
	}
}

func TestIPDecisions(t *testing.T) {
	e := mustEngine(t)
	cases := map[string]Action{
		"10.1.2.3":    ActionDirect, // 10/8
		"192.168.1.1": ActionDirect, // 192.168/16
		"1.2.4.9":     ActionDirect, // geoip cn
		"8.8.8.8":     ActionTunnel, // default
	}
	for ip, want := range cases {
		if got := e.DecideIP(netip.MustParseAddr(ip)); got != want {
			t.Errorf("DecideIP(%q) = %s, want %s", ip, got, want)
		}
	}
}

func TestDecideWithPort(t *testing.T) {
	e := mustEngine(t)
	if got := e.Decide("www.baidu.com:443"); got != ActionDirect {
		t.Errorf("host:port should strip port: got %s", got)
	}
	if got := e.Decide("10.0.0.1:22"); got != ActionDirect {
		t.Errorf("ip:port should strip port: got %s", got)
	}
}

func TestInvalidActionRejected(t *testing.T) {
	if _, err := Parse([]byte(`{"rules":[{"suffixes":["x"],"action":"nope"}]}`)); err == nil {
		t.Error("expected invalid-action error")
	}
}

func TestDefaultEngineTunnelsAll(t *testing.T) {
	e := Default()
	if e.Decide("anything.example") != ActionTunnel {
		t.Error("default engine should tunnel everything")
	}
}

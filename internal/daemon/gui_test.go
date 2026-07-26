package daemon_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/shan25519/ratelmesh/internal/daemon"
	"github.com/shan25519/ratelmesh/internal/wgengine"
)

// TestGUIServesControlPanel verifies ratelmeshd serves the self-contained web GUI and
// the local API over the GUI TCP address (DESIGN.md §3.4). ServeGUI does not use
// the unix socket path, so any placeholder is fine there.
func TestGUIServesControlPanel(t *testing.T) {
	d, err := daemon.New(daemon.Config{
		CoordURL: "http://127.0.0.1:1", // never started; we only probe the API surface
		StateDir: t.TempDir(), Hostname: "host", Engine: wgengine.NewStub(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const addr = "127.0.0.1:38089"
	go daemon.NewLocalAPI(d, "gui.sock").ServeGUI(ctx, addr)

	var body string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body = string(b)
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(body, "RatelMesh") {
		t.Fatalf("GUI page missing title, got %d bytes", len(body))
	}
	for _, want := range []string{"id=\"langsel\"", "Current route", "当前线路", "aria-pressed", "Connecting to EXIT", "EXIT selected; verifying traffic", "Devices using this EXIT", "exitTrafficVerified", "exitClients"} {
		if !strings.Contains(body, want) {
			t.Errorf("GUI page missing route/language affordance %q", want)
		}
	}
	for _, want := range []string{
		"RatelMesh honey badger Mesh mark",
		"--cyan:#20b9e8",
		"background:radial-gradient",
		"class=\"brand\"",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("GUI page missing unified brand marker %q", want)
		}
	}
	for _, legacy := range []string{"🦡 RatelMesh", "#b45309", "#16a34a", "#15803d"} {
		if strings.Contains(body, legacy) {
			t.Errorf("GUI page retained legacy brand token %q", legacy)
		}
	}
	for _, want := range []string{
		"id=\"doctorprivacy\"",
		"source or EXIT IP",
		"源 IP 或 EXIT IP",
		"Cloudflare reachability endpoints",
		"Cloudflare 连通性端点",
		"configured Coordinator, Relays and DNS resolver",
		"href=\"/privacy\"",
		"if(!window.confirm(T('doctorconsent')))return",
		"DOCTOR_DISCLOSURE_VERSION='v1'",
		"storageSet('ratelmeshdoctorconsent',DOCTOR_DISCLOSURE_VERSION)",
		"body:JSON.stringify({confirm:true,disclosureVersion:DOCTOR_DISCLOSURE_VERSION})",
		"body:JSON.stringify({action:action,confirm:true,disclosureVersion:DOCTOR_DISCLOSURE_VERSION})",
		"function storageGet(key){try{return localStorage.getItem(key);}catch(e){return null;}}",
		"function storageSet(key,value){try{localStorage.setItem(key,value);return true;}catch(e){return false;}}",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("GUI page missing first-run Network Doctor disclosure %q", want)
		}
	}
	if confirmAt, requestAt := strings.Index(body, "window.confirm(T('doctorconsent'))"), strings.Index(body, "fetch('/localapi/doctor'"); confirmAt < 0 || requestAt < 0 || confirmAt > requestAt {
		t.Errorf("Network Doctor disclosure must run before its active request: confirm=%d request=%d", confirmAt, requestAt)
	}

	privacy, err := http.Get("http://" + addr + "/privacy")
	if err != nil {
		t.Fatal(err)
	}
	privacyBody, _ := io.ReadAll(privacy.Body)
	privacy.Body.Close()
	if policy := privacy.Header.Get("Content-Security-Policy"); !strings.Contains(policy, "webrtc 'allow'") {
		t.Errorf("privacy page CSP must permit its local WebRTC test, got %q", policy)
	}
	for _, want := range []string{"Geographic privacy", "地理位置隐私", "stun:stun.ratelmesh.com:3479", "textContent"} {
		if !strings.Contains(string(privacyBody), want) {
			t.Errorf("privacy page missing %q", want)
		}
	}
	for _, want := range []string{"--cyan:#20b9e8", "background:radial-gradient", "color:#66d3f2"} {
		if !strings.Contains(string(privacyBody), want) {
			t.Errorf("privacy page missing unified brand marker %q", want)
		}
	}
	for _, legacy := range []string{"#b45309", "#f6f7f9", "#131519", "#1d2026"} {
		if strings.Contains(string(privacyBody), legacy) {
			t.Errorf("privacy page retained legacy brand token %q", legacy)
		}
	}
	if strings.Contains(string(privacyBody), "innerHTML") {
		t.Error("privacy page must not render diagnostic values through innerHTML")
	}

	// The local API is reachable over the same TCP listener.
	resp, err := http.Get("http://" + addr + "/localapi/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status endpoint = %d", resp.StatusCode)
	}
	resp.Body.Close()

	settingsResp, err := http.Post("http://"+addr+"/localapi/settings/internet-fallback?enabled=true", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	settingsResp.Body.Close()
	if settingsResp.StatusCode != http.StatusNoContent {
		t.Fatalf("internet fallback endpoint = %d", settingsResp.StatusCode)
	}
	if !d.Status().InternetFallback {
		t.Fatal("internet fallback endpoint did not update daemon state")
	}
}

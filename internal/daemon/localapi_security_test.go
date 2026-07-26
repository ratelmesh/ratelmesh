package daemon

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGUIRequiresLoopback ensures the unauthenticated local GUI can only bind to
// loopback, so it can never be exposed to the LAN (security review §5).
func TestGUIRequiresLoopback(t *testing.T) {
	ok := []string{"127.0.0.1:8088", "[::1]:8088", "127.0.0.53:53"}
	for _, a := range ok {
		if err := requireLoopback(a); err != nil {
			t.Errorf("requireLoopback(%q) = %v, want nil", a, err)
		}
	}
	bad := []string{"0.0.0.0:8088", "192.168.1.10:8088", ":8088", "example.com:8088"}
	for _, a := range bad {
		if err := requireLoopback(a); err == nil {
			t.Errorf("requireLoopback(%q) = nil, want error (non-loopback must be rejected)", a)
		}
	}
}

func TestBrowserGuardRejectsCrossSiteMutationAndDNSRebinding(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := browserGuard(next)

	tests := []struct {
		name   string
		host   string
		origin string
		site   string
		want   int
	}{
		{name: "same origin", host: "127.0.0.1:8088", origin: "http://127.0.0.1:8088", site: "same-origin", want: http.StatusNoContent},
		{name: "cross origin", host: "127.0.0.1:8088", origin: "https://evil.example", site: "cross-site", want: http.StatusForbidden},
		{name: "dns rebinding", host: "evil.example:8088", origin: "http://evil.example:8088", site: "same-origin", want: http.StatusForbidden},
		{name: "local CLI without browser headers", host: "localhost:8088", want: http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://"+tt.host+"/localapi/exit/clear", nil)
			req.Host = tt.host
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.site != "" {
				req.Header.Set("Sec-Fetch-Site", tt.site)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("status = %d, want %d", rr.Code, tt.want)
			}
			if rr.Header().Get("X-Frame-Options") != "DENY" {
				t.Fatal("security headers missing")
			}
		})
	}
}

// TestGUIDoesNotInnerHTMLResponseData verifies that the local GUI renders
// peer/self names via textContent, never innerHTML, so a
// client-chosen hostname can't inject script into the loopback GUI origin.
func TestGUIDoesNotInnerHTMLResponseData(t *testing.T) {
	if !strings.Contains(guiHTML, "textContent") {
		t.Fatal("GUI no longer uses textContent — response data may be unescaped")
	}
	// Ban ANY innerHTML assignment — response data must only reach the DOM via
	// textContent.
	if strings.Contains(guiHTML, "innerHTML") {
		t.Fatal("GUI still uses innerHTML somewhere — response data may be an XSS sink")
	}
}

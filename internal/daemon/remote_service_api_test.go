package daemon

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRemoteServiceStartRejectsCredentialsAndRequiresConfirmation(t *testing.T) {
	api := &LocalAPI{}
	tests := []struct {
		name string
		body string
		want int
	}{
		{name: "password forbidden", body: `{"service":"ssh","confirm":true,"password":"secret"}`, want: http.StatusBadRequest},
		{name: "username forbidden", body: `{"service":"ssh","confirm":true,"username":"root"}`, want: http.StatusBadRequest},
		{name: "confirmation required", body: `{"service":"ssh","confirm":false}`, want: http.StatusPreconditionRequired},
		{name: "trailing JSON forbidden", body: `{"service":"ssh","confirm":true}{}`, want: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/localapi/remote-services/start", strings.NewReader(test.body))
			rec := httptest.NewRecorder()
			api.handleRemoteServiceStart(rec, req)
			if rec.Code != test.want {
				t.Fatalf("status = %d, want %d; body=%q", rec.Code, test.want, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "secret") {
				t.Fatal("response reflected credential material")
			}
		})
	}
}

func TestRemoteServiceParserIsClosed(t *testing.T) {
	for _, name := range []string{"ssh", "RDP", " vnc "} {
		if _, ok := parseRemoteService(name); !ok {
			t.Fatalf("expected %q to be supported", name)
		}
	}
	for _, name := range []string{"", "ssh --flag", "telnet", "ssh\nrdp"} {
		if _, ok := parseRemoteService(name); ok {
			t.Fatalf("unexpected service %q accepted", name)
		}
	}
}

func TestRemoteServiceDetectionIsPostOnly(t *testing.T) {
	api := &LocalAPI{}
	req := httptest.NewRequest(http.MethodGet, "/localapi/remote-services", nil)
	rec := httptest.NewRecorder()
	api.buildMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET status=%d, want %d", rec.Code, http.StatusNotFound)
	}
}

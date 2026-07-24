package control

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCoordKeyRejectsNonSuccessResponse(t *testing.T) {
	key := make([]byte, 32)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"publicKey":"` + base64.StdEncoding.EncodeToString(key) + `"}`))
	}))
	defer ts.Close()

	c := NewClient(ts.URL+"/", "")
	if _, _, err := c.coordKey(t.Context()); err == nil || !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("coordKey error = %v, want status failure", err)
	}
}

func TestResetNetworkCancelsInflightRequest(t *testing.T) {
	started := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer ts.Close()

	c := NewClient(ts.URL, "")
	result := make(chan error, 1)
	go func() {
		_, _, err := c.coordKey(context.Background())
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("control request did not start")
	}
	c.ResetNetwork()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("request error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("network reset did not cancel control request")
	}
}

func TestCoordKeyAcceptsTrailingSlashBaseURL(t *testing.T) {
	key := make([]byte, 32)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/coordkey" {
			t.Fatalf("path = %q, want /v1/coordkey", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"publicKey":"` + base64.StdEncoding.EncodeToString(key) + `","nonce":"challenge"}`))
	}))
	defer ts.Close()

	c := NewClient(ts.URL+"/", "")
	if _, _, err := c.coordKey(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestCoordKeyAcceptsLegacyCoordinatorWithoutNonce(t *testing.T) {
	key := make([]byte, 32)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"publicKey":"` + base64.StdEncoding.EncodeToString(key) + `"}`))
	}))
	defer ts.Close()

	c := NewClient(ts.URL, "")
	if _, nonce, err := c.coordKey(t.Context()); err != nil || nonce != "" {
		t.Fatalf("legacy coord key nonce=%q err=%v", nonce, err)
	}
}

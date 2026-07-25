package dns

import (
	"errors"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestRunFirstSuccessfulFlushRequiresRealBackendSuccess(t *testing.T) {
	var calls []string
	runner := func(name string, args ...string) error {
		calls = append(calls, name)
		if name == "/second" {
			return nil
		}
		return errors.New("unavailable")
	}
	err := runFirstSuccessfulFlush(runner,
		cacheFlushCommand{name: "/first"},
		cacheFlushCommand{name: "/second"},
		cacheFlushCommand{name: "/third"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/first", "/second"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestRunFirstSuccessfulFlushFailsClosed(t *testing.T) {
	runner := func(string, ...string) error { return errors.New("unavailable") }
	if err := runFirstSuccessfulFlush(runner,
		cacheFlushCommand{name: "/first"},
		cacheFlushCommand{name: "/second"},
	); err == nil {
		t.Fatal("all unavailable cache backends reported success")
	}
	if err := runFirstSuccessfulFlush(nil); err == nil {
		t.Fatal("missing cache backend reported success")
	}
}

func TestNoopResolverDoesNotClaimCacheFlush(t *testing.T) {
	if err := (noopResolver{}).FlushCache(); err == nil {
		t.Fatal("unsupported resolver reported a successful cache flush")
	}
}

func TestCacheFlushCommandHasHardDeadline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses the POSIX shell")
	}
	start := time.Now()
	err := execCacheFlushCommandWithin(50*time.Millisecond, "/bin/sh", "-c", "sleep 10")
	if err == nil {
		t.Fatal("blocked cache flush command reported success")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("blocked cache flush command returned after %s", elapsed)
	}
}

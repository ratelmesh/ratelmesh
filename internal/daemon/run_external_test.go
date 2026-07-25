package daemon_test

import (
	"context"
	"testing"
	"time"

	"github.com/shan25519/ratelmesh/internal/daemon"
)

// runDaemon keeps test-owned state directories alive until the daemon has
// observed cancellation and completed any in-flight atomic state write.
func runDaemon(t *testing.T, ctx context.Context, d *daemon.Daemon) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = d.Run(ctx)
	}()
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("daemon did not stop within 3 seconds")
		}
	})
	return done
}

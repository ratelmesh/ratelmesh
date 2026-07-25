//go:build wgreal

package wgengine

import (
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/shan25519/ratelmesh/internal/types"
)

func TestParseUAPIPeerStatsIncludesEndpointAndTxBytes(t *testing.T) {
	key := types.Key{1, 2, 3}
	out := strings.Join([]string{
		"public_key=" + hex.EncodeToString(key[:]),
		"endpoint=198.51.100.44:61234",
		"last_handshake_time_sec=123",
		"last_handshake_time_nsec=456",
		"rx_bytes=789",
		"tx_bytes=4567",
		"",
	}, "\n")
	got := parseUAPIPeerStats(out)[key]
	if want := netip.MustParseAddrPort("198.51.100.44:61234"); got.Endpoint != want {
		t.Fatalf("endpoint = %v, want %v", got.Endpoint, want)
	}
	if !got.LatestHandshake.Equal(time.Unix(123, 456)) {
		t.Fatalf("handshake = %v, want %v", got.LatestHandshake, time.Unix(123, 456))
	}
	if got.RxBytes != 789 || got.TxBytes != 4567 {
		t.Fatalf("transfer counters = rx:%d tx:%d, want rx:789 tx:4567", got.RxBytes, got.TxBytes)
	}
}

package daemon

import (
	"net/netip"
	"testing"
	"time"

	"github.com/shan25519/ratelmesh/internal/types"
)

func TestExitClientStatusDistinguishesSelectedActiveAndOffline(t *testing.T) {
	now := time.Now()
	peer := types.Node{
		Name: "client-device", MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
		SelectedExitID: "mini-id", Online: true, LastSeen: now,
	}
	connecting, ok := exitClientStatus("mini-id", peer)
	if !ok || connecting.State != "connecting" || connecting.Name != "client-device" {
		t.Fatalf("connecting status = %+v, ok=%v", connecting, ok)
	}
	peer.ActiveExitID = "mini-id"
	active, ok := exitClientStatus("mini-id", peer)
	if !ok || active.State != "active" || active.MeshIP != "100.64.0.2" {
		t.Fatalf("active status = %+v, ok=%v", active, ok)
	}
	peer.Online = false
	offline, ok := exitClientStatus("mini-id", peer)
	if !ok || offline.State != "offline" {
		t.Fatalf("offline status = %+v, ok=%v", offline, ok)
	}
	if _, ok := exitClientStatus("different-exit", peer); ok {
		t.Fatal("client for a different exit was shown")
	}
}

func TestExitTrafficVerificationRequiresPostRouteProgressAndSurvivesIdle(t *testing.T) {
	private, _ := types.GenerateKey()
	key := private.Public()
	now := time.Now()
	d := &Daemon{
		exitPeerKey:      key,
		exitRouted:       true,
		exitTrafficAfter: now,
		rxProgress:       map[types.Key]time.Time{key: now.Add(-time.Second)},
		status:           Status{ActiveExit: "test-exit"},
	}
	if d.updateExitTrafficVerification(now.Add(time.Second)) || d.Status().ExitTrafficVerified {
		t.Fatal("traffic received before route activation was accepted as EXIT proof")
	}
	d.rxProgress[key] = now.Add(2 * time.Second)
	if !d.updateExitTrafficVerification(now.Add(3*time.Second)) || !d.Status().ExitTrafficVerified {
		t.Fatal("post-route encrypted receive progress did not verify EXIT traffic")
	}
	d.rxProgress[key] = now.Add(2 * time.Second)
	d.updateExitTrafficVerification(now.Add(livenessWindow + 3*time.Second))
	if !d.Status().ExitTrafficVerified {
		t.Fatal("an idle but still-routed EXIT lost its successful traffic proof")
	}
}

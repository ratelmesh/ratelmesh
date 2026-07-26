package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"
	"strings"

	"github.com/ratelmesh/ratelmesh/internal/remoteservice"
)

const maxRemoteServiceRequest = 4 << 10

type localServicePresence struct{}

func (localServicePresence) ConfirmServiceStart(context.Context, remoteservice.Target) error {
	// This confirmer is reachable only from the target-local API after the
	// request has supplied the exact explicit-confirmation boolean. Browser
	// callers additionally pass browserGuard's same-origin checks.
	return nil
}

type remoteServiceStatus struct {
	Service  string               `json:"service"`
	CanStart bool                 `json:"canStart"`
	Health   remoteservice.Health `json:"health"`
	Error    string               `json:"error,omitempty"`
}

type remoteServiceStartRequest struct {
	Service string `json:"service"`
	Confirm bool   `json:"confirm"`
}

func (a *LocalAPI) initRemoteServices() {
	a.remoteOnce.Do(func() {
		backend, err := remoteservice.NewSystemBackend()
		if err != nil {
			a.remoteErr = err
			return
		}
		confirmer, err := remoteservice.NewConfirmer(localServicePresence{}, remoteservice.Config{})
		if err != nil {
			a.remoteErr = err
			return
		}
		manager, err := remoteservice.NewManager(backend, confirmer, remoteservice.Config{})
		if err != nil {
			a.remoteErr = err
			return
		}
		a.remoteConfirmer = confirmer
		a.remoteManager = manager
	})
}

func (a *LocalAPI) handleRemoteServices(w http.ResponseWriter, r *http.Request) {
	a.initRemoteServices()
	w.Header().Set("Content-Type", "application/json")
	if a.remoteErr != nil {
		w.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": stableRemoteServiceError(a.remoteErr)})
		return
	}
	platform, ok := localRemotePlatform()
	if !ok {
		w.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(remoteservice.CodeUnsupportedTarget)})
		return
	}
	ctx := r.Context()
	out := make([]remoteServiceStatus, 0, len(localRemoteServiceKinds(platform)))
	for _, service := range localRemoteServiceKinds(platform) {
		target := a.localRemoteTarget(platform, service)
		health, err := a.remoteManager.Detect(ctx, target)
		item := remoteServiceStatus{
			Service:  remoteServiceName(service),
			CanStart: false, // production backends are detect-only until native atomic rollback ships.
			Health:   health,
		}
		if err != nil {
			item.Error = stableRemoteServiceError(err)
		}
		out = append(out, item)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"services": out})
}

func (a *LocalAPI) handleRemoteServiceStart(w http.ResponseWriter, r *http.Request) {
	var input remoteServiceStartRequest
	if err := decodeRemoteServiceRequest(r, &input); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !input.Confirm {
		http.Error(w, string(remoteservice.CodeConfirmationDenied), http.StatusPreconditionRequired)
		return
	}
	platform, ok := localRemotePlatform()
	if !ok {
		http.Error(w, string(remoteservice.CodeUnsupportedTarget), http.StatusNotImplemented)
		return
	}
	service, ok := parseRemoteService(input.Service)
	if !ok || !serviceAllowedOnPlatform(platform, service) {
		http.Error(w, string(remoteservice.CodeUnsupportedTarget), http.StatusUnprocessableEntity)
		return
	}
	a.initRemoteServices()
	if a.remoteErr != nil {
		http.Error(w, stableRemoteServiceError(a.remoteErr), http.StatusNotImplemented)
		return
	}
	target := a.localRemoteTarget(platform, service)
	token, err := a.remoteConfirmer.Confirm(r.Context(), target)
	if err != nil {
		http.Error(w, stableRemoteServiceError(err), http.StatusForbidden)
		return
	}
	result, err := a.remoteManager.EnsureRunning(r.Context(), remoteservice.Request{
		Target: target, Operation: remoteservice.OperationEnsureRunning, Confirmation: token,
	})
	if err != nil {
		status := http.StatusConflict
		if remoteservice.IsCode(err, remoteservice.CodeUnsupportedTarget) {
			status = http.StatusNotImplemented
		}
		http.Error(w, stableRemoteServiceError(err), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func decodeRemoteServiceRequest(r *http.Request, dst *remoteServiceStartRequest) error {
	if r == nil || r.Body == nil {
		return errors.New("missing body")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRemoteServiceRequest+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if strings.TrimSpace(dst.Service) == "" {
		return errors.New("missing service")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

func localRemotePlatform() (remoteservice.Platform, bool) {
	switch runtime.GOOS {
	case "linux":
		return remoteservice.PlatformLinux, true
	case "darwin":
		return remoteservice.PlatformMacOS, true
	case "windows":
		return remoteservice.PlatformWindows, true
	default:
		return remoteservice.PlatformUnknown, false
	}
}

func localRemoteServiceKinds(platform remoteservice.Platform) []remoteservice.ServiceKind {
	if platform == remoteservice.PlatformWindows {
		return []remoteservice.ServiceKind{remoteservice.ServiceSSH, remoteservice.ServiceRDP}
	}
	return []remoteservice.ServiceKind{remoteservice.ServiceSSH}
}

func serviceAllowedOnPlatform(platform remoteservice.Platform, service remoteservice.ServiceKind) bool {
	for _, allowed := range localRemoteServiceKinds(platform) {
		if service == allowed {
			return true
		}
	}
	return false
}

func parseRemoteService(value string) (remoteservice.ServiceKind, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ssh":
		return remoteservice.ServiceSSH, true
	case "rdp":
		return remoteservice.ServiceRDP, true
	case "vnc":
		return remoteservice.ServiceVNC, true
	default:
		return remoteservice.ServiceUnknown, false
	}
}

func remoteServiceName(service remoteservice.ServiceKind) string {
	switch service {
	case remoteservice.ServiceSSH:
		return "ssh"
	case remoteservice.ServiceRDP:
		return "rdp"
	case remoteservice.ServiceVNC:
		return "vnc"
	default:
		return "unknown"
	}
}

func (a *LocalAPI) localRemoteTarget(platform remoteservice.Platform, service remoteservice.ServiceKind) remoteservice.Target {
	a.d.mu.Lock()
	identity := a.d.nodeID
	if identity == "" {
		identity = a.d.machineIdentity
	}
	if identity == "" {
		identity = a.d.priv.Public().String()
	}
	a.d.mu.Unlock()
	return remoteservice.Target{
		Device:   remoteservice.DeviceID(sha256.Sum256([]byte("ratelmesh-device:" + identity))),
		Platform: platform,
		Service:  service,
	}
}

func stableRemoteServiceError(err error) string {
	var serviceErr *remoteservice.Error
	if errors.As(err, &serviceErr) {
		return string(serviceErr.Code)
	}
	return string(remoteservice.CodeUnsupportedTarget)
}

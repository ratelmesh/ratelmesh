package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shan25519/ratelmesh/internal/remoteservice"
)

// LocalAPI is ratelmeshd's loopback control surface, served over a unix socket that
// the CLI and GUI use (DESIGN.md §3.4). Unix uses a mode-0600 socket; Windows
// uses an ACL-protected named pipe. Neither platform exposes this API on a
// network interface.
type LocalAPI struct {
	d    *Daemon
	path string

	remoteOnce      sync.Once
	remoteManager   *remoteservice.Manager
	remoteConfirmer *remoteservice.Confirmer
	remoteErr       error
	doctorRunOnce   sync.Once
	doctorRun       chan struct{}
	doctorRepairMu  sync.Mutex
}

// NewLocalAPI creates the local API bound to socket path.
func NewLocalAPI(d *Daemon, socketPath string) *LocalAPI {
	return &LocalAPI{d: d, path: socketPath}
}

// Serve listens on the unix socket until ctx is cancelled.
func (a *LocalAPI) Serve(ctx context.Context) error {
	if err := ValidateSocketPath(a.path); err != nil {
		return err
	}
	ln, cleanup, err := listenLocal(a.path)
	if err != nil {
		return err
	}
	return a.serveMux(ctx, ln, cleanup)
}

// ServeGUI serves the same local API plus the web GUI over a TCP address, for a
// browser-based control panel (DESIGN.md §3.4). The address MUST be loopback:
// the GUI exposes status and exit switching with no auth, so binding it to a
// LAN/public interface would let anyone on the network read state and change the
// exit. Non-loopback binds are rejected.
func (a *LocalAPI) ServeGUI(ctx context.Context, addr string) error {
	if err := requireLoopback(addr); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return a.serveHandler(ctx, ln, browserGuard(a.buildMux()), func() {})
}

// requireLoopback ensures host:port binds only to a loopback address.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("gui: invalid address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("gui: address %q is not loopback; the local GUI must bind 127.0.0.1 or [::1] only", addr)
	}
	return nil
}

func (a *LocalAPI) serveMux(ctx context.Context, ln net.Listener, onClose func()) error {
	return a.serveHandler(ctx, ln, a.buildMux(), onClose)
}

func (a *LocalAPI) serveHandler(ctx context.Context, ln net.Listener, handler http.Handler, onClose func()) error {
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		onClose()
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// browserGuard protects the unauthenticated loopback GUI from cross-site POSTs
// and DNS rebinding. The unix-socket API does not need this middleware because
// browsers cannot connect to it and filesystem permissions are its trust gate.
func browserGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setBrowserSecurityHeaders(w)
		if !loopbackRequestHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" {
				http.Error(w, "cross-site request denied", http.StatusForbidden)
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin, r.Host) {
				http.Error(w, "cross-origin request denied", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func loopbackRequestHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func sameOrigin(origin, requestHost string) bool {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return strings.EqualFold(u.Host, requestHost)
}

func setBrowserSecurityHeaders(w http.ResponseWriter) {
	// The local privacy page deliberately creates a peer connection for its
	// user-triggered WebRTC leak test. Keep every ordinary network connection
	// same-origin, while permitting that browser primitive explicitly.
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; webrtc 'allow'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func (a *LocalAPI) buildMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/gui" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(guiHTML))
	})
	mux.HandleFunc("GET /privacy", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(privacyHTML))
	})
	mux.HandleFunc("GET /localapi/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a.d.Status())
	})
	mux.HandleFunc("POST /localapi/exit/use", func(w http.ResponseWriter, r *http.Request) {
		if err := a.d.SetExit(r.URL.Query().Get("name")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /localapi/exit/clear", func(w http.ResponseWriter, _ *http.Request) {
		if err := a.d.ClearExit(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /localapi/settings/internet-fallback", func(w http.ResponseWriter, r *http.Request) {
		enabled, err := strconv.ParseBool(r.URL.Query().Get("enabled"))
		if err != nil {
			http.Error(w, "enabled must be true or false", http.StatusBadRequest)
			return
		}
		if err := a.d.SetInternetFallback(enabled); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /localapi/location/system", func(w http.ResponseWriter, r *http.Request) {
		latitude, latErr := strconv.ParseFloat(r.URL.Query().Get("latitude"), 64)
		longitude, lonErr := strconv.ParseFloat(r.URL.Query().Get("longitude"), 64)
		if latErr != nil || lonErr != nil {
			http.Error(w, "valid latitude and longitude are required", http.StatusBadRequest)
			return
		}
		if err := a.d.SetSystemLocation(latitude, longitude); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /localapi/resolve", func(w http.ResponseWriter, r *http.Request) {
		ip, ok := a.d.Resolve(r.URL.Query().Get("name"))
		if !ok {
			http.Error(w, "NXDOMAIN", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"ip": ip})
	})
	mux.HandleFunc("POST /localapi/remote-services", a.handleRemoteServices)
	mux.HandleFunc("POST /localapi/remote-services/start", a.handleRemoteServiceStart)
	mux.HandleFunc("POST /localapi/doctor", a.handleDoctor)
	mux.HandleFunc("POST /localapi/doctor/repair", a.handleDoctorRepair)
	return mux
}

// localClient builds an HTTP client bound to the daemon's unix socket.
func localClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialLocal(ctx, socketPath)
			},
		},
		Timeout: 3 * time.Second,
	}
}

// FetchStatus is the client side: dial the unix socket and read status. Used by
// the `ratelmesh` CLI.
func FetchStatus(socketPath string) (Status, error) {
	resp, err := localClient(socketPath).Get("http://localapi/localapi/status")
	if err != nil {
		return Status{}, err
	}
	defer resp.Body.Close()
	var st Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return Status{}, err
	}
	return st, nil
}

// UseExit asks the daemon to route egress through the named exit node.
func UseExit(socketPath, name string) error {
	return postLocal(socketPath, "http://localapi/localapi/exit/use?name="+url.QueryEscape(name))
}

// ClearExit asks the daemon to resume direct egress.
func ClearExit(socketPath string) error {
	return postLocal(socketPath, "http://localapi/localapi/exit/clear")
}

// SetInternetFallback selects direct-internet availability over fail-closed
// leak protection when the selected exit becomes unavailable.
func SetInternetFallback(socketPath string, enabled bool) error {
	return postLocal(socketPath, "http://localapi/localapi/settings/internet-fallback?enabled="+strconv.FormatBool(enabled))
}

// Resolve asks the daemon to resolve a MagicDNS name to a mesh IP.
func Resolve(socketPath, name string) (string, error) {
	resp, err := localClient(socketPath).Get("http://localapi/localapi/resolve?name=" + url.QueryEscape(name))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s not found", name)
	}
	var out struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.IP, nil
}

func postLocal(socketPath, urlStr string) error {
	resp, err := localClient(socketPath).Post(urlStr, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s", strings.TrimSpace(string(body)))
	}
	return nil
}

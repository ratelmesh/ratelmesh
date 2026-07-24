package daemon

import (
	"net"
	"net/url"

	"github.com/ratelmesh/ratelmesh/internal/control"
	"github.com/ratelmesh/ratelmesh/internal/transport"
)

// newCoordClient builds the control-plane client for cfg.
//
// With CoordTransport unset (the default) it is the ordinary plain-HTTPS client —
// no behavior change for uncensored networks. With CoordTransport set it carries
// the coordinator's HTTP inside a camouflage transport so a client whose plain
// TLS to the coordinator's CDN host is throttled can still register. The
// coordinator URL is unchanged; only the carrier underneath is swapped.
func newCoordClient(cfg Config) *control.Client {
	if cfg.CoordTransport == "" {
		return control.NewClient(cfg.CoordURL, cfg.AuthKey)
	}
	frontDoor, serverName := coordFrontDoor(cfg.CoordURL, cfg.CoordFrontDoor)
	return control.NewCamoClient(cfg.CoordURL, cfg.AuthKey, coordTransport(cfg.CoordTransport, serverName), frontDoor)
}

// coordFrontDoor derives the dial target and the transport's server name (SNI +
// ws Host) from the coordinator URL and an optional explicit front door. When no
// front door is given it defaults to the coordinator host on :443, so the common
// case (CDN edge == coordinator hostname) needs no extra configuration.
func coordFrontDoor(coordURL, frontDoor string) (addr, serverName string) {
	serverName = coordURL
	if u, err := url.Parse(coordURL); err == nil && u.Hostname() != "" {
		serverName = u.Hostname()
	}
	if frontDoor == "" {
		return net.JoinHostPort(serverName, "443"), serverName
	}
	// An explicit front door may point at a different edge/IP; when it carries a
	// hostname (not a bare IP), that host names the TLS/ws identity to present.
	if host, _, err := net.SplitHostPort(frontDoor); err == nil && host != "" && net.ParseIP(host) == nil {
		serverName = host
	}
	return frontDoor, serverName
}

// coordTransport builds the client side of the named camouflage transport. It
// resolves "wss"/"wscamo" through their exported constructors (transport.New has
// no "wss" case) and defers anything else to transport.New.
func coordTransport(name, serverName string) transport.Transport {
	switch name {
	case "wss":
		return transport.NewWSSCamoClient(serverName)
	case "wscamo":
		return transport.NewWSCamoClient(serverName)
	default:
		return transport.New(name, []byte(serverName))
	}
}

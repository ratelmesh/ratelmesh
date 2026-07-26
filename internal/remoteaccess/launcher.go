package remoteaccess

import (
	"errors"
	"fmt"
	"net"
	"strconv"
)

var (
	ErrUnsupportedPlatformService = errors.New("unsupported service for platform")
)

// LauncherMetadata represents safe connection metadata.
// It explicitly excludes credentials, userinfo, queries, and fragments.
type LauncherMetadata struct {
	URI string `json:"uri"`
}

// GenerateLauncherMetadata returns a deterministic, safe protocol URI.
// It never outputs arbitrary URLs or shell commands.
func GenerateLauncherMetadata(grant *Grant) (*LauncherMetadata, error) {
	if grant == nil {
		return nil, ErrNilPointer
	}
	if err := grant.Service.Validate(); err != nil {
		return nil, err
	}

	ip := grant.Service.TargetMeshIP
	port := strconv.Itoa(int(grant.Service.Port))

	// Unambiguous fixed URI format: scheme://host:port
	// RFC 3986 compliance, explicitly excluding userinfo and path.
	// If IPv6, net.JoinHostPort correctly wraps it in brackets.
	hostPort := net.JoinHostPort(ip, port)

	// Validate platform compatibility.
	switch grant.Service.Platform {
	case PlatformMacOS:
		switch grant.Service.Kind {
		case KindSSH:
			return &LauncherMetadata{URI: fmt.Sprintf("ssh://%s", hostPort)}, nil
		case KindVNC:
			return &LauncherMetadata{URI: fmt.Sprintf("vnc://%s", hostPort)}, nil
		default:
			return nil, ErrUnsupportedPlatformService
		}
	case PlatformWindows:
		switch grant.Service.Kind {
		case KindSSH:
			return &LauncherMetadata{URI: fmt.Sprintf("ssh://%s", hostPort)}, nil
		case KindRDP:
			return &LauncherMetadata{URI: fmt.Sprintf("rdp://%s", hostPort)}, nil
		default:
			return nil, ErrUnsupportedPlatformService
		}
	case PlatformLinux:
		switch grant.Service.Kind {
		case KindSSH:
			return &LauncherMetadata{URI: fmt.Sprintf("ssh://%s", hostPort)}, nil
		case KindVNC:
			return &LauncherMetadata{URI: fmt.Sprintf("vnc://%s", hostPort)}, nil
		default:
			return nil, ErrUnsupportedPlatformService
		}
	default:
		return nil, ErrUnsupportedPlatformService
	}
}

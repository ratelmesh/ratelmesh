//go:build !linux && !darwin && !windows

package doctorplatform

import (
	"context"
	"errors"

	"github.com/shan25519/ratelmesh/internal/diagnose"
)

func currentPlatformOps() platformOps {
	unsupportedRoutes := func(context.Context, commandRunner, []interfaceInfo, string) ([]diagnose.Route, error) {
		return nil, errors.New("unsupported platform")
	}
	unsupportedDNS := func(context.Context, commandRunner, boundedFileReader, string) (diagnose.DNSState, error) {
		return diagnose.DNSState{}, errors.New("unsupported platform")
	}
	return platformOps{routes: unsupportedRoutes, dns: unsupportedDNS}
}

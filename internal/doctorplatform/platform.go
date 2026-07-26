package doctorplatform

import (
	"context"
	"errors"

	"github.com/ratelmesh/ratelmesh/internal/diagnose"
)

type platformOps struct {
	routes func(context.Context, commandRunner, []interfaceInfo, string) ([]diagnose.Route, error)
	dns    func(context.Context, commandRunner, boundedFileReader, string) (diagnose.DNSState, error)
}

func linuxPlatformOps() platformOps {
	return platformOps{routes: captureLinuxRoutes, dns: captureLinuxDNS}
}

func darwinPlatformOps() platformOps {
	return platformOps{routes: captureDarwinRoutes, dns: captureDarwinDNS}
}

func windowsPlatformOps() platformOps {
	return platformOps{routes: captureWindowsRoutes, dns: captureWindowsDNS}
}

func captureLinuxRoutes(ctx context.Context, runner commandRunner, _ []interfaceInfo, tunnel string) ([]diagnose.Route, error) {
	var out []diagnose.Route
	var observationErrors []error
	for _, item := range []struct {
		ruleSpec  commandSpec
		routeSpec commandSpec
		family    diagnose.AddressFamily
	}{
		{
			ruleSpec:  commandSpec{path: "/usr/sbin/ip", args: []string{"-j", "-4", "rule", "show"}},
			routeSpec: commandSpec{path: "/usr/sbin/ip", args: []string{"-j", "-4", "route", "show", "table", "main"}},
			family:    diagnose.FamilyV4,
		},
		{
			ruleSpec:  commandSpec{path: "/usr/sbin/ip", args: []string{"-j", "-6", "rule", "show"}},
			routeSpec: commandSpec{path: "/usr/sbin/ip", args: []string{"-j", "-6", "route", "show", "table", "main"}},
			family:    diagnose.FamilyV6,
		},
	} {
		rules, err := runner.run(ctx, item.ruleSpec)
		if err != nil {
			observationErrors = append(observationErrors, err)
			continue
		}
		if err := parseLinuxRules(rules); err != nil {
			observationErrors = append(observationErrors, err)
			continue
		}
		data, err := runner.run(ctx, item.routeSpec)
		if err != nil {
			observationErrors = append(observationErrors, err)
			continue
		}
		routes, err := parseLinuxMainRoutes(data, item.family, tunnel)
		if err != nil {
			observationErrors = append(observationErrors, err)
			continue
		}
		out = append(out, routes...)
	}
	return out, errors.Join(observationErrors...)
}

func captureLinuxDNS(ctx context.Context, _ commandRunner, reader boundedFileReader, tunnel string) (diagnose.DNSState, error) {
	data, err := reader.read(ctx, "/etc/resolv.conf", maxResolverSize)
	if err != nil {
		return diagnose.DNSState{}, err
	}
	return parseResolvConf(data, tunnel)
}

func captureDarwinRoutes(ctx context.Context, runner commandRunner, _ []interfaceInfo, tunnel string) ([]diagnose.Route, error) {
	var out []diagnose.Route
	for _, item := range []struct {
		spec   commandSpec
		family diagnose.AddressFamily
	}{
		{commandSpec{path: "/usr/sbin/netstat", args: []string{"-rn", "-f", "inet"}}, diagnose.FamilyV4},
		{commandSpec{path: "/usr/sbin/netstat", args: []string{"-rn", "-f", "inet6"}}, diagnose.FamilyV6},
	} {
		data, err := runner.run(ctx, item.spec)
		if err != nil {
			return nil, err
		}
		routes, err := parseDarwinRoutes(data, item.family, tunnel)
		if err != nil {
			return nil, err
		}
		out = append(out, routes...)
	}
	return out, nil
}

func captureDarwinDNS(ctx context.Context, runner commandRunner, _ boundedFileReader, tunnel string) (diagnose.DNSState, error) {
	data, err := runner.run(ctx, commandSpec{path: "/usr/sbin/scutil", args: []string{"--dns"}})
	if err != nil {
		return diagnose.DNSState{}, err
	}
	return parseDarwinDNS(data, tunnel)
}

func captureWindowsRoutes(ctx context.Context, runner commandRunner, infos []interfaceInfo, tunnel string) ([]diagnose.Route, error) {
	var out []diagnose.Route
	for _, item := range []struct {
		structured commandSpec
		family     diagnose.AddressFamily
	}{
		{
			structured: windowsPowerShellSpec(windowsRoutesIPv4Script),
			family:     diagnose.FamilyV4,
		},
		{
			structured: windowsPowerShellSpec(windowsRoutesIPv6Script),
			family:     diagnose.FamilyV6,
		},
	} {
		data, err := runner.run(ctx, item.structured)
		if err != nil {
			return nil, err
		}
		routes, err := parseWindowsStructuredRoutes(data, item.family, infos, tunnel)
		if err != nil {
			return nil, err
		}
		out = append(out, routes...)
	}
	return out, nil
}

func captureWindowsDNS(ctx context.Context, runner commandRunner, _ boundedFileReader, tunnel string) (diagnose.DNSState, error) {
	data, structuredErr := runner.run(ctx, windowsPowerShellSpec(windowsDNSScript))
	state, parseErr := parseWindowsStructuredDNS(data, tunnel)
	if structuredErr == nil && parseErr == nil {
		return state, nil
	}
	data, err := runner.run(ctx, commandSpec{path: `C:\Windows\System32\ipconfig.exe`, args: []string{"/all"}})
	if err != nil {
		return diagnose.DNSState{}, err
	}
	return parseWindowsDNS(data, tunnel)
}

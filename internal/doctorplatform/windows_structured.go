package doctorplatform

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
	"unicode"

	"github.com/ratelmesh/ratelmesh/internal/diagnose"
)

const (
	windowsPowerShellPath = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	windowsUTF8Prefix     = `$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$OutputEncoding=[Console]::OutputEncoding;`

	windowsRoutesIPv4Script = windowsUTF8Prefix +
		`ConvertTo-Json -Compress -InputObject @(Get-NetRoute -PolicyStore ActiveStore -AddressFamily IPv4 | ForEach-Object {[pscustomobject]@{destinationPrefix=$_.DestinationPrefix;interfaceIndex=$_.InterfaceIndex;nextHop=$_.NextHop;routeMetric=$_.RouteMetric}})`
	windowsRoutesIPv6Script = windowsUTF8Prefix +
		`ConvertTo-Json -Compress -InputObject @(Get-NetRoute -PolicyStore ActiveStore -AddressFamily IPv6 | ForEach-Object {[pscustomobject]@{destinationPrefix=$_.DestinationPrefix;interfaceIndex=$_.InterfaceIndex;nextHop=$_.NextHop;routeMetric=$_.RouteMetric}})`
	windowsDNSScript = windowsUTF8Prefix +
		`$servers=@(Get-DnsClientServerAddress | ForEach-Object {[pscustomobject]@{interfaceAlias=$_.InterfaceAlias;serverAddresses=@($_.ServerAddresses)}});` +
		`$domains=@((Get-DnsClientGlobalSetting).SuffixSearchList)+@(Get-DnsClient | ForEach-Object {$_.ConnectionSpecificSuffix});` +
		`[pscustomobject]@{servers=$servers;searchDomains=@($domains | Where-Object {$_})}|ConvertTo-Json -Compress -Depth 4`
)

var (
	windowsRouteFields = map[string]bool{
		"destinationPrefix": true,
		"interfaceIndex":    true,
		"nextHop":           true,
		"routeMetric":       true,
	}
	windowsDNSFields = map[string]bool{
		"servers":       true,
		"searchDomains": true,
	}
	windowsDNSServerFields = map[string]bool{
		"interfaceAlias":  true,
		"serverAddresses": true,
	}
)

func windowsPowerShellSpec(script string) commandSpec {
	return commandSpec{
		path: windowsPowerShellPath,
		args: []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script},
	}
}

func parseWindowsStructuredRoutes(
	data []byte,
	family diagnose.AddressFamily,
	infos []interfaceInfo,
	tunnel string,
) ([]diagnose.Route, error) {
	entries, err := decodeJSONArray(data, maxRouteCount)
	if err != nil {
		return nil, err
	}
	indexNames := make(map[int]string, len(infos))
	for _, info := range infos {
		if info.Index <= 0 || info.Name == "" || len(info.Name) > 256 {
			return nil, errMalformed
		}
		if _, duplicate := indexNames[info.Index]; duplicate {
			return nil, errMalformed
		}
		indexNames[info.Index] = info.Name
	}
	routes := make([]diagnose.Route, 0, len(entries))
	for _, raw := range entries {
		fields, err := decodeStrictObject(raw, windowsRouteFields)
		if err != nil || len(fields) != len(windowsRouteFields) {
			return nil, errMalformed
		}
		destination, err := jsonString(fields["destinationPrefix"])
		if err != nil {
			return nil, errMalformed
		}
		prefix, err := parseRoutePrefix(destination, family)
		if err != nil {
			return nil, errMalformed
		}
		index, err := jsonInt(fields["interfaceIndex"])
		if err != nil || index <= 0 {
			return nil, errMalformed
		}
		iface, ok := indexNames[index]
		if !ok {
			return nil, errMalformed
		}
		nextHopRaw, err := jsonString(fields["nextHop"])
		if err != nil {
			return nil, errMalformed
		}
		nextHop, err := netip.ParseAddr(nextHopRaw)
		if err != nil || nextHop.Is4() != prefix.Addr().Is4() {
			return nil, errMalformed
		}
		metric, err := jsonInt(fields["routeMetric"])
		if err != nil || metric < 0 {
			return nil, errMalformed
		}
		routes = append(routes, classifyWindowsStructuredRoute(prefix, iface, tunnel, index, nextHop, metric))
	}
	return routes, nil
}

// classifyWindowsStructuredRoute recognizes Windows blackhole-route semantics:
// software loopback, an unspecified same-family next hop, and route metric zero.
// The prefix is deliberately unrestricted because wgengine applies the same
// representation to every configured block route. Interface index 1 alone is
// not proof; ordinary Windows loopback routes use other metrics or next hops.
func classifyWindowsStructuredRoute(
	prefix netip.Prefix,
	iface, tunnel string,
	interfaceIndex int,
	nextHop netip.Addr,
	routeMetric int,
) diagnose.Route {
	if interfaceIndex == 1 &&
		routeMetric == 0 &&
		nextHop.IsUnspecified() &&
		nextHop.Is4() == prefix.Addr().Is4() {
		return diagnose.Route{
			Destination: prefix,
			Interface:   iface,
			Kind:        diagnose.RouteKindBlackhole,
		}
	}
	return *classifiedRoute(prefix, iface, tunnel)
}

func parseWindowsStructuredDNS(data []byte, tunnel string) (diagnose.DNSState, error) {
	if len(data) > maxCommandSize {
		return diagnose.DNSState{}, errOversized
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return diagnose.DNSState{}, errMalformed
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return diagnose.DNSState{}, errMalformed
	}
	fields, err := decodeStrictObject(raw, windowsDNSFields)
	if err != nil || len(fields) != len(windowsDNSFields) {
		return diagnose.DNSState{}, errMalformed
	}

	var serverEntries []json.RawMessage
	if err := json.Unmarshal(fields["servers"], &serverEntries); err != nil || len(serverEntries) > maxDNSItems {
		return diagnose.DNSState{}, errMalformed
	}
	searchDomains, err := strictStringArray(fields["searchDomains"], maxDNSItems)
	if err != nil {
		return diagnose.DNSState{}, err
	}

	var state diagnose.DNSState
	totalServers, tunnelServers := 0, 0
	for _, entry := range serverEntries {
		server, err := decodeStrictObject(entry, windowsDNSServerFields)
		if err != nil || len(server) != len(windowsDNSServerFields) {
			return diagnose.DNSState{}, errMalformed
		}
		iface, err := jsonString(server["interfaceAlias"])
		if err != nil || !validWindowsInterfaceName(iface) {
			return diagnose.DNSState{}, errMalformed
		}
		addresses, err := strictStringArray(server["serverAddresses"], maxDNSItems)
		if err != nil {
			return diagnose.DNSState{}, err
		}
		for _, rawAddress := range addresses {
			addr, err := parseResolverAddr(rawAddress)
			if err != nil {
				return diagnose.DNSState{}, errMalformed
			}
			state.Servers = appendUniqueAddr(state.Servers, addr)
			totalServers++
			if tunnel != "" && iface == tunnel {
				tunnelServers++
			}
			if totalServers+len(searchDomains) > maxDNSItems {
				return diagnose.DNSState{}, errOversized
			}
		}
	}
	for _, domain := range searchDomains {
		if !validDomain(domain) {
			return diagnose.DNSState{}, errMalformed
		}
		state.SearchDomains = appendUniqueString(state.SearchDomains, strings.TrimSuffix(domain, "."))
	}
	if len(state.Servers)+len(state.SearchDomains) > maxDNSItems {
		return diagnose.DNSState{}, errOversized
	}
	state.ViaTunnel = totalServers > 0 && tunnelServers == totalServers
	return state, nil
}

func strictStringArray(raw json.RawMessage, max int) ([]string, error) {
	var values []string
	if raw == nil || json.Unmarshal(raw, &values) != nil {
		return nil, errMalformed
	}
	if len(values) > max {
		return nil, errOversized
	}
	for _, value := range values {
		if value == "" || len(value) > maxDomainSize+16 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return nil, errMalformed
		}
	}
	return values, nil
}

func validWindowsInterfaceName(name string) bool {
	return name != "" && len(name) <= 256 && strings.IndexFunc(name, unicode.IsControl) < 0
}

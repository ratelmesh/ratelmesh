package doctorplatform

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/shan25519/ratelmesh/internal/diagnose"
)

const (
	maxLineSize   = 16 << 10
	maxRouteCount = 16384
	maxLinuxRules = 64
)

var linuxRuleFields = map[string]bool{
	"priority": true, "src": true, "table": true, "action": true, "protocol": true,
}

var linuxRouteFields = map[string]bool{
	"type": true, "dst": true, "dev": true, "protocol": true, "scope": true,
	"src": true, "prefsrc": true, "gateway": true, "metric": true, "flags": true,
	"metrics": true, "nexthops": true, "pref": true, "expires": true, "mtu": true,
	"table": true, "nhid": true, "via": true,
}

var linuxNexthopFields = map[string]bool{
	"gateway": true, "dev": true, "weight": true, "flags": true, "via": true,
}

func parseLinuxRules(data []byte) error {
	entries, err := decodeJSONArray(data, maxLinuxRules)
	if err != nil {
		return err
	}
	want := map[int]string{0: "local", 32766: "main", 32767: "default"}
	seen := make(map[int]bool)
	for _, raw := range entries {
		fields, err := decodeStrictObject(raw, linuxRuleFields)
		if err != nil {
			return err
		}
		priority, err := jsonInt(fields["priority"])
		if err != nil {
			return errMalformed
		}
		table, err := jsonTable(fields["table"])
		if err != nil {
			return errMalformed
		}
		expected, ok := want[priority]
		if !ok || table != expected || seen[priority] {
			return errMalformed
		}
		seen[priority] = true
		src, err := jsonString(fields["src"])
		if err != nil || src != "all" {
			return errMalformed
		}
		if actionRaw, ok := fields["action"]; ok {
			action, err := jsonString(actionRaw)
			if err != nil || (action != "lookup" && action != "to_tbl") {
				return errMalformed
			}
		}
		if protocolRaw, ok := fields["protocol"]; ok {
			protocol, err := jsonString(protocolRaw)
			if err != nil || protocol != "kernel" {
				return errMalformed
			}
		}
	}
	if len(seen) != len(want) {
		return errMalformed
	}
	return nil
}

func parseLinuxMainRoutes(data []byte, family diagnose.AddressFamily, tunnel string) ([]diagnose.Route, error) {
	entries, err := decodeJSONArray(data, maxRouteCount)
	if err != nil {
		return nil, err
	}
	routes := make([]diagnose.Route, 0, len(entries))
	for _, raw := range entries {
		fields, err := decodeStrictObject(raw, linuxRouteFields)
		if err != nil {
			return nil, err
		}
		route, err := parseLinuxMainRoute(fields, family, tunnel)
		if err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func parseLinuxMainRoute(fields map[string]json.RawMessage, family diagnose.AddressFamily, tunnel string) (diagnose.Route, error) {
	routeType := ""
	if raw, ok := fields["type"]; ok {
		var err error
		routeType, err = jsonString(raw)
		if err != nil {
			return diagnose.Route{}, errMalformed
		}
	}
	dstRaw, ok := fields["dst"]
	if !ok {
		return diagnose.Route{}, errMalformed
	}
	dst, err := jsonString(dstRaw)
	if err != nil {
		return diagnose.Route{}, errMalformed
	}
	prefix, err := parseRoutePrefix(dst, family)
	if err != nil {
		return diagnose.Route{}, errMalformed
	}
	if err := validateLinuxRouteMetadata(fields, family); err != nil {
		return diagnose.Route{}, err
	}

	kind := diagnose.RouteKindPhysical
	if routeType == "blackhole" || routeType == "unreachable" || routeType == "prohibit" {
		if _, hasDev := fields["dev"]; hasDev {
			return diagnose.Route{}, errMalformed
		}
		if _, hasNexthops := fields["nexthops"]; hasNexthops {
			return diagnose.Route{}, errMalformed
		}
		kind = diagnose.RouteKindBlackhole
		return diagnose.Route{Destination: prefix, Kind: kind}, nil
	}
	if routeType != "" && routeType != "unicast" {
		return diagnose.Route{}, errMalformed
	}

	iface, err := linuxRouteInterface(fields)
	if err != nil {
		return diagnose.Route{}, err
	}
	if tunnel != "" && iface == tunnel {
		kind = diagnose.RouteKindTunnel
	}
	return diagnose.Route{
		Destination: prefix,
		Interface:   iface,
		ViaTunnel:   kind == diagnose.RouteKindTunnel,
		Kind:        kind,
	}, nil
}

func linuxRouteInterface(fields map[string]json.RawMessage) (string, error) {
	iface := ""
	if raw, ok := fields["dev"]; ok {
		var err error
		iface, err = jsonString(raw)
		if err != nil || iface == "" || len(iface) > 256 {
			return "", errMalformed
		}
	}
	if raw, ok := fields["nexthops"]; ok {
		var hops []json.RawMessage
		if err := json.Unmarshal(raw, &hops); err != nil || len(hops) == 0 || len(hops) > 64 {
			return "", errMalformed
		}
		for _, hopRaw := range hops {
			hop, err := decodeStrictObject(hopRaw, linuxNexthopFields)
			if err != nil {
				return "", err
			}
			dev, err := jsonString(hop["dev"])
			if err != nil || dev == "" || len(dev) > 256 {
				return "", errMalformed
			}
			if iface == "" {
				iface = dev
			} else if iface != dev {
				return "", errMalformed
			}
			if err := validateNexthop(hop); err != nil {
				return "", err
			}
		}
	}
	if iface == "" {
		return "", errMalformed
	}
	return iface, nil
}

func validateLinuxRouteMetadata(fields map[string]json.RawMessage, family diagnose.AddressFamily) error {
	for _, key := range []string{"protocol", "scope", "src", "prefsrc", "gateway", "via"} {
		if raw, ok := fields[key]; ok {
			if value, err := jsonString(raw); err != nil || value == "" || len(value) > 256 {
				return errMalformed
			}
		}
	}
	for _, key := range []string{"metric", "expires", "mtu", "nhid"} {
		if raw, ok := fields[key]; ok {
			if _, err := jsonUint(raw); err != nil {
				return errMalformed
			}
		}
	}
	if raw, ok := fields["table"]; ok {
		table, err := jsonTable(raw)
		if err != nil || table != "main" {
			return errMalformed
		}
	}
	if raw, ok := fields["flags"]; ok {
		if err := validateStringArray(raw, 64); err != nil {
			return err
		}
	}
	if raw, ok := fields["metrics"]; ok {
		if err := validateNumericObject(raw, 64); err != nil {
			return err
		}
	}
	if raw, ok := fields["pref"]; ok {
		pref, err := jsonString(raw)
		if err != nil || family != diagnose.FamilyV6 ||
			(pref != "low" && pref != "medium" && pref != "high") {
			return errMalformed
		}
	}
	return nil
}

func validateNexthop(fields map[string]json.RawMessage) error {
	for _, key := range []string{"gateway", "via"} {
		if raw, ok := fields[key]; ok {
			if value, err := jsonString(raw); err != nil || value == "" || len(value) > 256 {
				return errMalformed
			}
		}
	}
	if raw, ok := fields["weight"]; ok {
		if _, err := jsonUint(raw); err != nil {
			return errMalformed
		}
	}
	if raw, ok := fields["flags"]; ok {
		return validateStringArray(raw, 64)
	}
	return nil
}

func decodeJSONArray(data []byte, max int) ([]json.RawMessage, error) {
	if len(data) > maxCommandSize {
		return nil, errOversized
	}
	var entries []json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&entries); err != nil {
		return nil, errMalformed
	}
	if len(entries) > max {
		return nil, errOversized
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errMalformed
	}
	return entries, nil
}

func decodeStrictObject(raw json.RawMessage, allowed map[string]bool) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errMalformed
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || !allowed[key] {
			return nil, errMalformed
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, errMalformed
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errMalformed
		}
		fields[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errMalformed
	}
	return fields, nil
}

func jsonString(raw json.RawMessage) (string, error) {
	if raw == nil {
		return "", errMalformed
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", errMalformed
	}
	return value, nil
}

func jsonInt(raw json.RawMessage) (int, error) {
	var value int
	if raw == nil || json.Unmarshal(raw, &value) != nil {
		return 0, errMalformed
	}
	return value, nil
}

func jsonUint(raw json.RawMessage) (uint64, error) {
	var value uint64
	if json.Unmarshal(raw, &value) != nil {
		return 0, errMalformed
	}
	return value, nil
}

func jsonTable(raw json.RawMessage) (string, error) {
	if value, err := jsonString(raw); err == nil {
		switch value {
		case "local", "255":
			return "local", nil
		case "main", "254":
			return "main", nil
		case "default", "253":
			return "default", nil
		}
		return "", errMalformed
	}
	value, err := jsonUint(raw)
	if err != nil {
		return "", errMalformed
	}
	switch value {
	case 255:
		return "local", nil
	case 254:
		return "main", nil
	case 253:
		return "default", nil
	default:
		return "", errMalformed
	}
}

func validateStringArray(raw json.RawMessage, max int) error {
	var values []string
	if json.Unmarshal(raw, &values) != nil || len(values) > max {
		return errMalformed
	}
	for _, value := range values {
		if len(value) > 256 {
			return errMalformed
		}
	}
	return nil
}

func validateNumericObject(raw json.RawMessage, max int) error {
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil || len(values) > max {
		return errMalformed
	}
	for key, value := range values {
		if key == "" || len(key) > 64 {
			return errMalformed
		}
		if _, err := jsonUint(value); err != nil {
			return errMalformed
		}
	}
	return nil
}

func parseDarwinRoutes(data []byte, family diagnose.AddressFamily, tunnel string) ([]diagnose.Route, error) {
	return scanRouteLines(data, func(line string) (*diagnose.Route, error) {
		fields := strings.Fields(line)
		if len(fields) == 0 ||
			strings.HasPrefix(line, "Routing tables") ||
			strings.HasPrefix(line, "Internet") ||
			fields[0] == "Destination" {
			return nil, nil
		}
		if len(fields) < 4 || len(fields) > 16 {
			return nil, errMalformed
		}
		dst, err := parseDarwinPrefix(fields[0], family)
		if err != nil {
			return nil, errMalformed
		}
		flags := fields[2]
		iface := fields[3]
		// "Expire" may be absent but Netif is always immediately after Flags.
		if len(iface) > 256 {
			return nil, errMalformed
		}
		kind := diagnose.RouteKindPhysical
		if strings.ContainsAny(flags, "BR") {
			kind = diagnose.RouteKindBlackhole
		} else if tunnel != "" && iface == tunnel {
			kind = diagnose.RouteKindTunnel
		}
		return &diagnose.Route{
			Destination: dst,
			Interface:   iface,
			ViaTunnel:   kind == diagnose.RouteKindTunnel,
			Kind:        kind,
		}, nil
	})
}

func parseWindowsRoutes(data []byte, family diagnose.AddressFamily, infos []interfaceInfo, tunnel string) ([]diagnose.Route, error) {
	addressNames := make(map[netip.Addr]string)
	indexNames := make(map[int]string)
	for _, info := range infos {
		indexNames[info.Index] = info.Name
		for _, raw := range info.Addrs {
			if prefix, err := netip.ParsePrefix(withoutZone(raw)); err == nil {
				addressNames[prefix.Addr().Unmap()] = info.Name
			}
		}
	}
	active := false
	recognizedTable := false
	recognizedActive := false
	routes, err := scanRouteLines(data, func(line string) (*diagnose.Route, error) {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.EqualFold(trimmed, "Active Routes:"):
			active = true
			recognizedActive = true
			return nil, nil
		case strings.EqualFold(trimmed, "Persistent Routes:"):
			active = false
			return nil, nil
		case trimmed == "IPv4 Route Table":
			recognizedTable = family == diagnose.FamilyV4
			return nil, nil
		case trimmed == "IPv6 Route Table":
			recognizedTable = family == diagnose.FamilyV6
			return nil, nil
		case strings.HasPrefix(trimmed, "Interface List"),
			strings.HasPrefix(trimmed, "Network Destination"),
			strings.HasPrefix(trimmed, "If "),
			strings.HasPrefix(trimmed, "==="),
			trimmed == "",
			trimmed == "None":
			return nil, nil
		}
		if !active {
			return nil, nil
		}
		fields := strings.Fields(trimmed)
		if family == diagnose.FamilyV4 {
			if len(fields) != 5 {
				return nil, errMalformed
			}
			addr, err := netip.ParseAddr(fields[0])
			if err != nil || !addr.Is4() {
				return nil, errMalformed
			}
			mask, err := netip.ParseAddr(fields[1])
			if err != nil || !mask.Is4() {
				return nil, errMalformed
			}
			bits, ok := maskBits(mask)
			if !ok {
				return nil, errMalformed
			}
			ifaceAddr, err := netip.ParseAddr(fields[3])
			if err != nil {
				return nil, errMalformed
			}
			iface := addressNames[ifaceAddr.Unmap()]
			return classifiedRoute(netip.PrefixFrom(addr, bits).Masked(), iface, tunnel), nil
		}
		if len(fields) != 4 {
			return nil, errMalformed
		}
		index, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, errMalformed
		}
		dst, err := parseRoutePrefix(fields[2], diagnose.FamilyV6)
		if err != nil {
			return nil, errMalformed
		}
		return classifiedRoute(dst, indexNames[index], tunnel), nil
	})
	if err != nil {
		return nil, err
	}
	if !recognizedTable || !recognizedActive {
		return nil, errMalformed
	}
	return routes, nil
}

func classifiedRoute(dst netip.Prefix, iface, tunnel string) *diagnose.Route {
	kind := diagnose.RouteKindPhysical
	if tunnel != "" && iface == tunnel {
		kind = diagnose.RouteKindTunnel
	}
	return &diagnose.Route{
		Destination: dst,
		Interface:   iface,
		ViaTunnel:   kind == diagnose.RouteKindTunnel,
		Kind:        kind,
	}
}

func scanRouteLines(data []byte, parse func(string) (*diagnose.Route, error)) ([]diagnose.Route, error) {
	if len(data) > maxCommandSize {
		return nil, errOversized
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), maxLineSize)
	var routes []diagnose.Route
	for scanner.Scan() {
		route, err := parse(scanner.Text())
		if err != nil {
			return nil, errMalformed
		}
		if route != nil {
			routes = append(routes, *route)
			if len(routes) > maxRouteCount {
				return nil, errOversized
			}
		}
	}
	if scanner.Err() != nil {
		return nil, errOversized
	}
	return routes, nil
}

func parseRoutePrefix(raw string, family diagnose.AddressFamily) (netip.Prefix, error) {
	if raw == "default" {
		if family == diagnose.FamilyV4 {
			return netip.MustParsePrefix("0.0.0.0/0"), nil
		}
		return netip.MustParsePrefix("::/0"), nil
	}
	if !strings.Contains(raw, "/") {
		addr, err := netip.ParseAddr(strings.TrimSuffix(raw, "%"+zone(raw)))
		if err != nil {
			return netip.Prefix{}, err
		}
		if (family == diagnose.FamilyV4) != addr.Is4() {
			return netip.Prefix{}, errors.New("wrong family")
		}
		return netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()).Masked()
	if (family == diagnose.FamilyV4) != prefix.Addr().Is4() {
		return netip.Prefix{}, errors.New("wrong family")
	}
	return prefix, nil
}

func parseDarwinPrefix(raw string, family diagnose.AddressFamily) (netip.Prefix, error) {
	if family == diagnose.FamilyV6 {
		if percent := strings.IndexByte(raw, '%'); percent >= 0 {
			slash := strings.IndexByte(raw[percent:], '/')
			if slash >= 0 {
				raw = raw[:percent] + raw[percent+slash:]
			} else {
				raw = raw[:percent]
			}
		}
		return parseRoutePrefix(raw, family)
	}
	if raw == "default" {
		return parseRoutePrefix(raw, family)
	}
	parts := strings.SplitN(raw, "/", 2)
	octets := strings.Split(parts[0], ".")
	if len(octets) < 1 || len(octets) > 4 {
		return netip.Prefix{}, errors.New("bad IPv4 route")
	}
	for len(octets) < 4 {
		octets = append(octets, "0")
	}
	addr, err := netip.ParseAddr(strings.Join(octets, "."))
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 8 * len(strings.Split(parts[0], "."))
	if len(parts) == 2 {
		bits, err = strconv.Atoi(parts[1])
		if err != nil || bits < 0 || bits > 32 {
			return netip.Prefix{}, errors.New("bad prefix bits")
		}
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}

func zone(raw string) string {
	if i := strings.LastIndexByte(raw, '%'); i >= 0 {
		return raw[i+1:]
	}
	return ""
}

func maskBits(mask netip.Addr) (int, bool) {
	b := mask.As4()
	bits := 0
	zeroSeen := false
	for _, octet := range b {
		for bit := 7; bit >= 0; bit-- {
			one := octet&(1<<bit) != 0
			if zeroSeen && one {
				return 0, false
			}
			if one {
				bits++
			} else {
				zeroSeen = true
			}
		}
	}
	return bits, true
}

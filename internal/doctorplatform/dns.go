package doctorplatform

import (
	"bufio"
	"bytes"
	"net/netip"
	"strings"
	"unicode"

	"github.com/ratelmesh/ratelmesh/internal/diagnose"
)

const (
	maxDNSItems   = 256
	maxDomainSize = 253
)

func parseResolvConf(data []byte, _ string) (diagnose.DNSState, error) {
	if len(data) > maxResolverSize {
		return diagnose.DNSState{}, errOversized
	}
	var state diagnose.DNSState
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), maxLineSize)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "nameserver":
			if len(fields) != 2 {
				return diagnose.DNSState{}, errMalformed
			}
			addr, err := parseResolverAddr(fields[1])
			if err != nil {
				return diagnose.DNSState{}, errMalformed
			}
			state.Servers = appendUniqueAddr(state.Servers, addr)
		case "search":
			if len(fields) < 2 {
				return diagnose.DNSState{}, errMalformed
			}
			for _, domain := range fields[1:] {
				if !validDomain(domain) {
					return diagnose.DNSState{}, errMalformed
				}
				state.SearchDomains = appendUniqueString(state.SearchDomains, strings.TrimSuffix(domain, "."))
			}
		case "domain":
			if len(fields) != 2 || !validDomain(fields[1]) {
				return diagnose.DNSState{}, errMalformed
			}
			state.SearchDomains = appendUniqueString(state.SearchDomains, strings.TrimSuffix(fields[1], "."))
		case "options", "sortlist":
			// These directives do not contribute to the doctor's minimal view.
		default:
			return diagnose.DNSState{}, errMalformed
		}
		if len(state.Servers)+len(state.SearchDomains) > maxDNSItems {
			return diagnose.DNSState{}, errOversized
		}
	}
	if scanner.Err() != nil {
		return diagnose.DNSState{}, errOversized
	}
	return state, nil
}

func parseDarwinDNS(data []byte, tunnel string) (diagnose.DNSState, error) {
	if len(data) > maxCommandSize {
		return diagnose.DNSState{}, errOversized
	}
	type resolver struct {
		servers []netip.Addr
		search  []string
		iface   string
	}
	var blocks []resolver
	var current *resolver
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), maxLineSize)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "DNS configuration") {
			continue
		}
		if strings.HasPrefix(line, "resolver #") {
			blocks = append(blocks, resolver{})
			current = &blocks[len(blocks)-1]
			continue
		}
		if current == nil {
			return diagnose.DNSState{}, errMalformed
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return diagnose.DNSState{}, errMalformed
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case strings.HasPrefix(key, "nameserver["):
			addr, err := parseResolverAddr(value)
			if err != nil {
				return diagnose.DNSState{}, errMalformed
			}
			current.servers = appendUniqueAddr(current.servers, addr)
		case strings.HasPrefix(key, "search domain["):
			if !validDomain(value) {
				return diagnose.DNSState{}, errMalformed
			}
			current.search = appendUniqueString(current.search, strings.TrimSuffix(value, "."))
		case key == "if_index":
			if open := strings.IndexByte(value, '('); open >= 0 && strings.HasSuffix(value, ")") {
				current.iface = strings.TrimSpace(value[open+1 : len(value)-1])
				if current.iface == "" || len(current.iface) > 256 {
					return diagnose.DNSState{}, errMalformed
				}
			}
		default:
			// scutil emits bounded metadata (flags, reach, order, timeout).
		}
	}
	if scanner.Err() != nil {
		return diagnose.DNSState{}, errOversized
	}

	state := diagnose.DNSState{}
	allTunnel := true
	serverBlocks := 0
	for _, block := range blocks {
		if len(block.servers) > 0 {
			serverBlocks++
			if tunnel == "" || block.iface != tunnel {
				allTunnel = false
			}
		}
		for _, addr := range block.servers {
			state.Servers = appendUniqueAddr(state.Servers, addr)
		}
		for _, domain := range block.search {
			state.SearchDomains = appendUniqueString(state.SearchDomains, domain)
		}
		if len(state.Servers)+len(state.SearchDomains) > maxDNSItems {
			return diagnose.DNSState{}, errOversized
		}
	}
	state.ViaTunnel = serverBlocks > 0 && allTunnel
	return state, nil
}

func parseWindowsDNS(data []byte, tunnel string) (diagnose.DNSState, error) {
	if len(data) > maxCommandSize {
		return diagnose.DNSState{}, errOversized
	}
	var state diagnose.DNSState
	var currentInterface string
	var dnsContinuation bool
	var searchContinuation bool
	var tunnelServers, totalServers int
	recognizedHeader := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), maxLineSize)
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" {
			dnsContinuation = false
			searchContinuation = false
			continue
		}
		if line == "Windows IP Configuration" {
			recognizedHeader = true
			continue
		}
		if !unicode.IsSpace([]rune(raw)[0]) && strings.HasSuffix(line, ":") &&
			strings.Contains(strings.ToLower(line), " adapter ") {
			heading := strings.TrimSuffix(line, ":")
			lower := strings.ToLower(heading)
			currentInterface = strings.TrimSpace(heading[strings.Index(lower, " adapter ")+len(" adapter "):])
			dnsContinuation = false
			searchContinuation = false
			continue
		}
		if dnsContinuation {
			if addr, err := parseResolverAddr(line); err == nil {
				state.Servers = appendUniqueAddr(state.Servers, addr)
				totalServers++
				if currentInterface == tunnel {
					tunnelServers++
				}
				continue
			}
			if !strings.Contains(line, ":") {
				return diagnose.DNSState{}, errMalformed
			}
			dnsContinuation = false
		}
		if searchContinuation {
			if !strings.Contains(line, ":") {
				if !validDomain(line) {
					return diagnose.DNSState{}, errMalformed
				}
				state.SearchDomains = appendUniqueString(state.SearchDomains, strings.TrimSuffix(line, "."))
				continue
			}
			searchContinuation = false
		}
		key, value, hasColon := strings.Cut(line, ":")
		if hasColon {
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
			normalizedKey := normalizeWindowsKey(key)
			dnsContinuation = false
			searchContinuation = false
			switch {
			case normalizedKey == "DNS Servers":
				dnsContinuation = true
				if value != "" {
					addr, err := parseResolverAddr(value)
					if err != nil {
						return diagnose.DNSState{}, errMalformed
					}
					state.Servers = appendUniqueAddr(state.Servers, addr)
					totalServers++
					if currentInterface == tunnel {
						tunnelServers++
					}
				}
			case normalizedKey == "DNS Suffix Search List":
				searchContinuation = true
				if value != "" {
					if !validDomain(value) {
						return diagnose.DNSState{}, errMalformed
					}
					state.SearchDomains = appendUniqueString(state.SearchDomains, strings.TrimSuffix(value, "."))
				}
			case strings.HasSuffix(normalizedKey, "Connection-specific DNS Suffix"):
				if value != "" {
					if !validDomain(value) {
						return diagnose.DNSState{}, errMalformed
					}
					state.SearchDomains = appendUniqueString(state.SearchDomains, strings.TrimSuffix(value, "."))
				}
			}
			continue
		}
		if len(state.Servers)+len(state.SearchDomains) > maxDNSItems {
			return diagnose.DNSState{}, errOversized
		}
	}
	if scanner.Err() != nil {
		return diagnose.DNSState{}, errOversized
	}
	if !recognizedHeader {
		return diagnose.DNSState{}, errMalformed
	}
	state.ViaTunnel = totalServers > 0 && tunnelServers == totalServers
	return state, nil
}

func normalizeWindowsKey(key string) string {
	key = strings.Map(func(r rune) rune {
		if r == '.' {
			return ' '
		}
		return r
	}, key)
	return strings.Join(strings.Fields(key), " ")
}

func parseResolverAddr(raw string) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if percent := strings.LastIndexByte(raw, '%'); percent >= 0 {
		raw = raw[:percent]
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr.Unmap(), nil
}

func validDomain(raw string) bool {
	raw = strings.TrimSuffix(raw, ".")
	if raw == "" || len(raw) > maxDomainSize {
		return false
	}
	for _, label := range strings.Split(raw, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') ||
				(r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') ||
				r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

func appendUniqueAddr(items []netip.Addr, item netip.Addr) []netip.Addr {
	for _, existing := range items {
		if existing == item {
			return items
		}
	}
	return append(items, item)
}

func appendUniqueString(items []string, item string) []string {
	for _, existing := range items {
		if existing == item {
			return items
		}
	}
	return append(items, item)
}

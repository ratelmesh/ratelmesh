package magicsock

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const upnpMaxBody = 1 << 20
const upnpSearchTarget = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"

type upnpService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

type upnpDevice struct {
	Services []upnpService `xml:"serviceList>service"`
	Devices  []upnpDevice  `xml:"deviceList>device"`
}

type upnpRoot struct {
	Device upnpDevice `xml:"device"`
}

func mapUPnP(ctx context.Context, gateway, local netip.Addr, internalPort uint16, lifetime time.Duration) (PortMapping, error) {
	if !gateway.Is4() || !local.Is4() {
		return PortMapping{}, errors.New("magicsock: UPnP discovery requires IPv4")
	}
	locations, err := discoverUPnP(ctx, gateway, local)
	if err != nil {
		return PortMapping{}, err
	}
	var lastErr error
	for _, location := range locations {
		mapping, err := mapUPnPLocation(ctx, location, gateway, local, internalPort, lifetime)
		if err == nil {
			return mapping, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no usable UPnP IGD service")
	}
	return PortMapping{}, fmt.Errorf("magicsock: UPnP mapping: %w", lastErr)
}

func discoverUPnP(ctx context.Context, gateway, local netip.Addr) ([]*url.URL, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(local.AsSlice())})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	request := strings.Join([]string{
		"M-SEARCH * HTTP/1.1",
		"HOST: 239.255.255.250:1900",
		`MAN: "ssdp:discover"`,
		"MX: 1",
		"ST: " + upnpSearchTarget,
		"", "",
	}, "\r\n")
	target := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	if _, err := conn.WriteToUDP([]byte(request), target); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(1500 * time.Millisecond)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	_ = conn.SetReadDeadline(deadline)
	seen := make(map[string]bool)
	var locations []*url.URL
	buf := make([]byte, 64<<10)
	for len(locations) < 8 {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		response := string(buf[:n])
		if !validSSDPResponse(response, from, gateway) {
			continue
		}
		location := ssdpHeader(response, "location")
		parsed, err := url.Parse(strings.TrimSpace(location))
		// SSDP is unauthenticated. Only the default gateway is entitled to make
		// the privileged daemon issue HTTP/SOAP requests; otherwise any LAN host
		// could advertise an arbitrary private or loopback URL and turn discovery
		// into an SSRF primitive.
		if err != nil || !safeUPnPURLForHost(parsed, gateway) || seen[parsed.String()] {
			continue
		}
		seen[parsed.String()] = true
		locations = append(locations, parsed)
	}
	if len(locations) == 0 {
		return nil, errors.New("magicsock: no UPnP IGD discovered")
	}
	return locations, nil
}

func validSSDPResponse(response string, from *net.UDPAddr, gateway netip.Addr) bool {
	if from == nil || !gateway.IsValid() || from.AddrPort().Addr().Unmap() != gateway.Unmap() {
		return false
	}
	lines := strings.Split(response, "\r\n")
	if len(lines) == 0 {
		return false
	}
	status := strings.Fields(lines[0])
	if len(status) < 3 ||
		(status[0] != "HTTP/1.1" && status[0] != "HTTP/1.0") ||
		status[1] != "200" {
		return false
	}
	return ssdpHeader(response, "st") == upnpSearchTarget
}

func ssdpHeader(response, name string) string {
	for _, line := range strings.Split(response, "\r\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(key), name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func safeUPnPURL(value *url.URL) bool {
	if value == nil || value.Scheme != "http" || value.User != nil || value.Hostname() == "" {
		return false
	}
	host, err := netip.ParseAddr(value.Hostname())
	return err == nil && (host.IsPrivate() || host.IsLinkLocalUnicast() || host.IsLoopback())
}

func safeUPnPURLForHost(value *url.URL, expected netip.Addr) bool {
	if !safeUPnPURL(value) || !expected.IsValid() {
		return false
	}
	host, err := netip.ParseAddr(value.Hostname())
	return err == nil && host.Unmap() == expected.Unmap()
}

func mapUPnPLocation(ctx context.Context, location *url.URL, gateway, local netip.Addr, internalPort uint16, lifetime time.Duration) (PortMapping, error) {
	if !safeUPnPURLForHost(location, gateway) {
		return PortMapping{}, errors.New("unsafe UPnP description URL")
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || !safeUPnPURLForHost(req.URL, gateway) {
				return errors.New("unsafe UPnP redirect")
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location.String(), nil)
	if err != nil {
		return PortMapping{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return PortMapping{}, err
	}
	body, err := readUPnPBody(resp)
	if err != nil {
		return PortMapping{}, err
	}
	var root upnpRoot
	if err := xml.Unmarshal(body, &root); err != nil {
		return PortMapping{}, err
	}
	service, ok := findUPnPService(root.Device)
	if !ok {
		return PortMapping{}, errors.New("WANIPConnection/WANPPPConnection service missing")
	}
	control, err := location.Parse(service.ControlURL)
	if err != nil || !safeUPnPURLForHost(control, gateway) {
		return PortMapping{}, errors.New("unsafe UPnP control URL")
	}
	externalText, err := upnpSOAP(ctx, client, control, service.ServiceType, "GetExternalIPAddress", "")
	if err != nil {
		return PortMapping{}, err
	}
	external, err := extractUPnPAddress(externalText)
	if err != nil {
		return PortMapping{}, err
	}
	seconds := int64(lifetime / time.Second)
	arguments := fmt.Sprintf(
		"<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>%d</NewInternalPort><NewInternalClient>%s</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>RatelMesh</NewPortMappingDescription><NewLeaseDuration>%d</NewLeaseDuration>",
		internalPort, internalPort, local, seconds,
	)
	if _, err := upnpSOAP(ctx, client, control, service.ServiceType, "AddPortMapping", arguments); err != nil {
		return PortMapping{}, err
	}
	return PortMapping{
		External:     netip.AddrPortFrom(external, internalPort),
		Gateway:      mustURLAddress(location),
		InternalPort: internalPort,
		Protocol:     "upnp",
		Lifetime:     lifetime,
	}, nil
}

func readUPnPBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("UPnP HTTP status %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, upnpMaxBody+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) > upnpMaxBody {
		return nil, errors.New("UPnP response too large")
	}
	return body, nil
}

func findUPnPService(device upnpDevice) (upnpService, bool) {
	for _, service := range device.Services {
		if validUPnPServiceType(service.ServiceType) {
			return service, true
		}
	}
	for _, child := range device.Devices {
		if service, ok := findUPnPService(child); ok {
			return service, true
		}
	}
	return upnpService{}, false
}

func validUPnPServiceType(value string) bool {
	for _, prefix := range []string{
		"urn:schemas-upnp-org:service:WANIPConnection:",
		"urn:schemas-upnp-org:service:WANPPPConnection:",
	} {
		if strings.HasPrefix(value, prefix) {
			version := strings.TrimPrefix(value, prefix)
			parsed, err := strconv.ParseUint(version, 10, 16)
			return err == nil && parsed > 0
		}
	}
	return false
}

func upnpSOAP(ctx context.Context, client *http.Client, control *url.URL, serviceType, action, arguments string) (string, error) {
	envelope := `<?xml version="1.0"?>` +
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>` +
		`<u:` + action + ` xmlns:u="` + serviceType + `">` + arguments + `</u:` + action + `>` +
		`</s:Body></s:Envelope>`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, control.String(), bytes.NewBufferString(envelope))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", strconv.Quote(serviceType+"#"+action))
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	body, err := readUPnPBody(resp)
	return string(body), err
}

func extractUPnPAddress(body string) (netip.Addr, error) {
	decoder := xml.NewDecoder(strings.NewReader(body))
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "NewExternalIPAddress" {
			continue
		}
		var text string
		if err := decoder.DecodeElement(&text, &start); err != nil {
			return netip.Addr{}, err
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(text))
		if err == nil && addr.IsValid() && !addr.IsUnspecified() {
			return addr.Unmap(), nil
		}
	}
	return netip.Addr{}, errors.New("UPnP external address missing")
}

func mustURLAddress(value *url.URL) netip.Addr {
	addr, _ := netip.ParseAddr(value.Hostname())
	return addr.Unmap()
}

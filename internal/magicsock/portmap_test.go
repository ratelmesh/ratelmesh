package magicsock

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPCPMapUDP(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		buf := make([]byte, 128)
		n, from, err := server.ReadFromUDP(buf)
		if err != nil || n != 60 {
			return
		}
		resp := make([]byte, 60)
		resp[0], resp[1] = 2, 0x81
		binary.BigEndian.PutUint32(resp[4:8], 3600)
		copy(resp[24:36], buf[24:36])
		resp[36] = 17
		copy(resp[40:42], buf[40:42])
		binary.BigEndian.PutUint16(resp[42:44], 42424)
		putPCPAddress(resp[44:60], netip.MustParseAddr("203.0.113.9"))
		_, _ = server.WriteToUDP(resp, from)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	mapping, err := mapPCPAt(ctx, server.LocalAddr().(*net.UDPAddr).AddrPort(), netip.MustParseAddr("192.168.1.10"), 51820, 7200)
	if err != nil {
		t.Fatal(err)
	}
	if mapping.Protocol != "pcp" || mapping.External != netip.MustParseAddrPort("203.0.113.9:42424") || mapping.InternalPort != 51820 || mapping.Lifetime != time.Hour {
		t.Fatalf("mapping = %+v", mapping)
	}
}

func TestNATPMPMapUDPAllowsUpstreamPrivateAddress(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		buf := make([]byte, 32)
		n, from, err := server.ReadFromUDP(buf)
		if err != nil || n != 2 {
			return
		}
		publicResp := make([]byte, 12)
		publicResp[1] = 128
		copy(publicResp[8:12], netip.MustParseAddr("192.168.1.50").AsSlice())
		_, _ = server.WriteToUDP(publicResp, from)
		n, from, err = server.ReadFromUDP(buf)
		if err != nil || n != 12 {
			return
		}
		mapResp := make([]byte, 16)
		mapResp[1] = 129
		copy(mapResp[8:10], buf[4:6])
		binary.BigEndian.PutUint16(mapResp[10:12], 51820)
		binary.BigEndian.PutUint32(mapResp[12:16], 7200)
		_, _ = server.WriteToUDP(mapResp, from)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	mapping, err := mapNATPMPAt(ctx, server.LocalAddr().(*net.UDPAddr).AddrPort(), 51820, 7200)
	if err != nil {
		t.Fatal(err)
	}
	if mapping.Protocol != "nat-pmp" || mapping.External != netip.MustParseAddrPort("192.168.1.50:51820") || mapping.Lifetime != 2*time.Hour {
		t.Fatalf("mapping = %+v", mapping)
	}
}

func TestUPnPMapUDP(t *testing.T) {
	var mu sync.Mutex
	actions := make([]string, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/root.xml":
			_, _ = w.Write([]byte(`<?xml version="1.0"?><root><device><deviceList><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType><controlURL>/control</controlURL></service></serviceList></device></deviceList></device></root>`))
		case "/control":
			action := r.Header.Get("SOAPAction")
			mu.Lock()
			actions = append(actions, action)
			mu.Unlock()
			if strings.Contains(action, "GetExternalIPAddress") {
				_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2"><NewExternalIPAddress>203.0.113.77</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`))
				return
			}
			if !strings.Contains(action, "AddPortMapping") {
				http.Error(w, "unexpected action", http.StatusBadRequest)
				return
			}
			body, _ := io.ReadAll(io.LimitReader(r.Body, 16<<10))
			if !bytes.Contains(body, []byte("<NewInternalPort>51820</NewInternalPort>")) || !bytes.Contains(body, []byte("<NewProtocol>UDP</NewProtocol>")) {
				http.Error(w, "bad mapping", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body/></s:Envelope>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	location, err := url.Parse(server.URL + "/root.xml")
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := netip.ParseAddr(location.Hostname())
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := mapUPnPLocation(context.Background(), location, gateway, netip.MustParseAddr("192.168.1.10"), 51820, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if mapping.Protocol != "upnp" || mapping.External != netip.MustParseAddrPort("203.0.113.77:51820") {
		t.Fatalf("mapping = %+v", mapping)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(actions) != 2 || !strings.Contains(actions[0], "GetExternalIPAddress") || !strings.Contains(actions[1], "AddPortMapping") {
		t.Fatalf("SOAP actions = %v", actions)
	}
}

func TestUPnPRejectsCrossHostDescriptionAndControlURLs(t *testing.T) {
	gateway := netip.MustParseAddr("192.168.1.1")
	for _, raw := range []string{
		"http://127.0.0.1:8080/root.xml",
		"http://192.168.1.22:8080/root.xml",
		"http://10.0.0.1:8080/root.xml",
	} {
		location, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if safeUPnPURLForHost(location, gateway) {
			t.Fatalf("accepted UPnP URL %q for gateway %s", raw, gateway)
		}
	}
	location, err := url.Parse("http://192.168.1.1:5431/root.xml")
	if err != nil {
		t.Fatal(err)
	}
	if !safeUPnPURLForHost(location, gateway) {
		t.Fatalf("rejected same-gateway UPnP URL %q", location)
	}
}

func TestSSDPResponseMustComeFromGatewayWithExpectedStatusAndTarget(t *testing.T) {
	gateway := netip.MustParseAddr("192.168.1.1")
	fromGateway := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.168.1.1:1900"))
	valid := "HTTP/1.1 200 OK\r\n" +
		"ST: " + upnpSearchTarget + "\r\n" +
		"LOCATION: http://192.168.1.1:5431/root.xml\r\n\r\n"
	if !validSSDPResponse(valid, fromGateway, gateway) {
		t.Fatal("rejected valid gateway SSDP response")
	}
	cases := []struct {
		name     string
		response string
		from     *net.UDPAddr
	}{
		{
			name:     "wrong source",
			response: valid,
			from:     net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.168.1.22:1900")),
		},
		{
			name:     "non-success status",
			response: strings.Replace(valid, "200 OK", "404 Not Found", 1),
			from:     fromGateway,
		},
		{
			name:     "unexpected search target",
			response: strings.Replace(valid, upnpSearchTarget, "upnp:rootdevice", 1),
			from:     fromGateway,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if validSSDPResponse(tc.response, tc.from, gateway) {
				t.Fatalf("accepted invalid SSDP response: %q", tc.response)
			}
		})
	}
}

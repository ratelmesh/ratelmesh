package dns

import (
	"reflect"
	"testing"
)

func TestParseWindowsDNSUpstreams(t *testing.T) {
	got := parseWindowsDNSUpstreams("192.168.1.1\r\n127.0.0.1\r\n2001:4860:4860::8888\r\n192.168.1.1\r\n::1\r\n")
	want := []string{"192.168.1.1:53", "[2001:4860:4860::8888]:53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("upstreams = %v, want %v", got, want)
	}
}

func TestParseWindowsDNSUpstreamsSkipsNoise(t *testing.T) {
	if got := parseWindowsDNSUpstreams("not-an-address\r\n0.0.0.0\r\n::\r\n"); len(got) != 0 {
		t.Fatalf("upstreams = %v, want none", got)
	}
}

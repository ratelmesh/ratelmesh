package georegion

import "testing"

func TestFromCoordinates(t *testing.T) {
	tests := []struct {
		lat, lon float64
		want     string
	}{{34.05, -118.24, "north-america-west"}, {40.71, -74.0, "north-america-east"}, {51.5, -0.1, "europe-west"}, {35.68, 139.69, "asia-east"}, {-33.86, 151.2, "oceania"}, {1.35, 103.8, "asia-southeast"}}
	for _, tc := range tests {
		if got := FromCoordinates(tc.lat, tc.lon); got != tc.want {
			t.Errorf("FromCoordinates(%v, %v) = %q, want %q", tc.lat, tc.lon, got, tc.want)
		}
	}
	if got := FromCoordinates(100, 0); got != "" {
		t.Fatalf("invalid coordinates returned %q", got)
	}
}

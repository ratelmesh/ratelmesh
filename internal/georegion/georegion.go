// Package georegion converts authorized system coordinates into the coarse
// regions used by the tenant map. Exact coordinates stay on the device.
package georegion

import "math"

// FromCoordinates returns a deliberately coarse, non-empty region for valid
// WGS84 coordinates. Boundaries are approximate product regions, not countries.
func FromCoordinates(latitude, longitude float64) string {
	if math.IsNaN(latitude) || math.IsNaN(longitude) || math.IsInf(latitude, 0) || math.IsInf(longitude, 0) || latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180 {
		return ""
	}
	switch {
	case latitude < -10 && longitude >= 110:
		return "oceania"
	case longitude < -30 && latitude < 15:
		return "south-america"
	case longitude < -30:
		if longitude <= -100 {
			return "north-america-west"
		}
		return "north-america-east"
	case longitude < 30 && latitude >= 35:
		if longitude < 15 {
			return "europe-west"
		}
		return "europe-east"
	case longitude < 55 && latitude < 35:
		return "africa"
	case longitude < 75 && latitude >= 10:
		return "middle-east"
	case longitude < 100:
		return "asia-south"
	case longitude < 125 && latitude < 25:
		return "asia-southeast"
	case longitude >= 110 && latitude < -10:
		return "oceania"
	default:
		return "asia-east"
	}
}

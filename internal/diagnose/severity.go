package diagnose

import (
	"fmt"
)

// Severity ranks a Finding from healthy to user-impacting. It is ordered: a
// larger value is more severe, so findings and reports can be sorted and the
// worst result surfaced first.
type Severity int

const (
	// SeverityOK is a healthy, positive result (the probe found nothing wrong).
	SeverityOK Severity = iota
	// SeverityInfo is a neutral observation with no action implied.
	SeverityInfo
	// SeverityWarning is a degraded-but-functioning condition worth attention.
	SeverityWarning
	// SeverityCritical is a broken, user-impacting condition.
	SeverityCritical
)

// severityNames maps each severity to its stable wire string. The strings are
// part of the report contract and must not change.
var severityNames = map[Severity]string{
	SeverityOK:       "ok",
	SeverityInfo:     "info",
	SeverityWarning:  "warning",
	SeverityCritical: "critical",
}

// String returns the stable lower-case name of the severity.
func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return fmt.Sprintf("severity(%d)", int(s))
}

// Valid reports whether s is one of the defined severities.
func (s Severity) Valid() bool {
	_, ok := severityNames[s]
	return ok
}

// MarshalText renders the severity as its stable name so it serialises as a
// string in JSON rather than an integer.
func (s Severity) MarshalText() ([]byte, error) {
	if !s.Valid() {
		return nil, fmt.Errorf("diagnose: invalid severity %d", int(s))
	}
	return []byte(s.String()), nil
}

// UnmarshalText parses a severity name produced by MarshalText.
func (s *Severity) UnmarshalText(b []byte) error {
	if v, ok := ParseSeverity(string(b)); ok {
		*s = v
		return nil
	}
	return fmt.Errorf("diagnose: unknown severity %q", string(b))
}

// ParseSeverity maps a wire name back to a Severity. The bool is false for an
// unknown name.
func ParseSeverity(name string) (Severity, bool) {
	for sev, n := range severityNames {
		if n == name {
			return sev, true
		}
	}
	return 0, false
}

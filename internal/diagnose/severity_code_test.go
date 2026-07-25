package diagnose

import (
	"encoding/json"
	"testing"
)

func TestSeverityRoundTrip(t *testing.T) {
	for _, s := range []Severity{SeverityOK, SeverityInfo, SeverityWarning, SeverityCritical} {
		b, err := s.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText(%v): %v", s, err)
		}
		var back Severity
		if err := back.UnmarshalText(b); err != nil {
			t.Fatalf("UnmarshalText(%q): %v", b, err)
		}
		if back != s {
			t.Fatalf("round trip changed %v -> %v", s, back)
		}
		if parsed, ok := ParseSeverity(s.String()); !ok || parsed != s {
			t.Fatalf("ParseSeverity(%q) = %v,%v", s.String(), parsed, ok)
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	if !(SeverityOK < SeverityInfo && SeverityInfo < SeverityWarning && SeverityWarning < SeverityCritical) {
		t.Fatal("severities must be strictly ordered OK < Info < Warning < Critical")
	}
}

func TestSeverityInvalid(t *testing.T) {
	bad := Severity(99)
	if bad.Valid() {
		t.Fatal("Severity(99) should be invalid")
	}
	if _, err := bad.MarshalText(); err == nil {
		t.Fatal("marshalling an invalid severity should error")
	}
	if _, ok := ParseSeverity("nonsense"); ok {
		t.Fatal("ParseSeverity should reject unknown names")
	}
}

func TestSeverityJSONIsString(t *testing.T) {
	b, err := json.Marshal(SeverityCritical)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"critical"` {
		t.Fatalf("severity should marshal as a string, got %s", b)
	}
}

func TestCodeCatalogConsistent(t *testing.T) {
	if len(AllCodes()) != len(codeCatalog) {
		t.Fatalf("AllCodes() returned %d, catalog has %d", len(AllCodes()), len(codeCatalog))
	}
	for c, meta := range codeCatalog {
		if !c.Known() {
			t.Errorf("code %q not reported as known", c)
		}
		if !meta.Severity.Valid() {
			t.Errorf("code %q has invalid severity", c)
		}
		if meta.Title == "" {
			t.Errorf("code %q has an empty title", c)
		}
		if c.DefaultSeverity() != meta.Severity {
			t.Errorf("code %q DefaultSeverity mismatch", c)
		}
	}
}

func TestUnknownCodeDefaults(t *testing.T) {
	c := Code("nope.not_real")
	if c.Known() {
		t.Fatal("bogus code should be unknown")
	}
	if c.DefaultSeverity() != SeverityInfo {
		t.Fatalf("unknown code should default to info, got %v", c.DefaultSeverity())
	}
	if c.Title() != string(c) {
		t.Fatalf("unknown code title should echo the code, got %q", c.Title())
	}
}

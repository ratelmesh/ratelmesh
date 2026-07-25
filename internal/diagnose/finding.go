package diagnose

import "sort"

// Finding is a single observation produced by a probe. It is deliberately
// structured: the human-readable text lives in Summary and any variable data
// lives in Evidence, and both are passed through the Redactor when the report
// is serialised. Probes should therefore never embed a raw secret in a Finding,
// but even if one does, it cannot reach the emitted JSON.
type Finding struct {
	// Code is the stable machine identifier for the condition.
	Code Code `json:"code"`
	// Severity ranks the finding. It defaults to the code's registered
	// severity but a probe may raise or lower it for context.
	Severity Severity `json:"severity"`
	// Probe is the probe that produced the finding.
	Probe ProbeID `json:"probe"`
	// Summary is a short, human-readable description (redacted at report time).
	Summary string `json:"summary"`
	// Evidence holds structured, variable detail (values redacted at report
	// time). Keys are fixed schema names and are never redacted.
	Evidence map[string]string `json:"evidence,omitempty"`
}

// newFinding builds a Finding for code with the code's default severity. The
// evidence map may be nil.
func newFinding(probe ProbeID, code Code, summary string, evidence map[string]string) Finding {
	return Finding{
		Code:     code,
		Severity: code.DefaultSeverity(),
		Probe:    probe,
		Summary:  summary,
		Evidence: evidence,
	}
}

// sortFindings orders findings deterministically: by the canonical probe order,
// then most-severe first, then by code, then by summary. It sorts in place.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if oi, oj := probeOrder(a.Probe), probeOrder(b.Probe); oi != oj {
			return oi < oj
		}
		if a.Severity != b.Severity {
			return a.Severity > b.Severity // most severe first
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Summary < b.Summary
	})
}

// worstSeverity returns the highest severity among fs, or SeverityOK if empty.
func worstSeverity(fs []Finding) Severity {
	worst := SeverityOK
	for _, f := range fs {
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	return worst
}

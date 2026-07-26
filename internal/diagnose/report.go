package diagnose

import (
	"encoding/json"
	"sort"
	"time"
)

// reportSchema identifies the report contract version. Bump it only for a
// breaking change to the emitted shape.
const reportSchema = "ratelmesh.diagnose.report/v2"

// Report is the machine-readable outcome of a doctor run. Its Go fields are
// typed for callers that consume it in-process; its JSON encoding is the shared
// support artifact and is always redacted (see MarshalJSON).
type Report struct {
	Schema      string
	GeneratedAt time.Time
	Summary     ReportSummary
	Findings    []Finding
	Probes      []ProbeOutcome

	// redactor is the run's redactor, applied as the final serialisation step.
	// It is unexported and never emitted.
	redactor *Redactor
}

// ReportSummary is the at-a-glance verdict over all findings.
type ReportSummary struct {
	OK               bool
	WorstSeverity    Severity
	TotalFindings    int
	CountsBySeverity map[Severity]int
}

// ProbeOutcome is the per-probe execution record (without the findings, which
// live in Report.Findings).
type ProbeOutcome struct {
	Probe        ProbeID
	Status       ProbeStatus
	Duration     time.Duration
	FindingCount int
}

// buildReport assembles a Report from raw probe results: it orders results and
// findings deterministically, computes the summary, and attaches the redactor.
func buildReport(now time.Time, results []ProbeResult, red *Redactor) Report {
	sort.SliceStable(results, func(i, j int) bool {
		return probeOrder(results[i].Probe) < probeOrder(results[j].Probe)
	})

	var findings []Finding
	outcomes := make([]ProbeOutcome, 0, len(results))
	for _, r := range results {
		findings = append(findings, r.Findings...)
		outcomes = append(outcomes, ProbeOutcome{
			Probe:        r.Probe,
			Status:       r.Status,
			Duration:     r.Duration,
			FindingCount: len(r.Findings),
		})
	}
	sortFindings(findings)

	return Report{
		Schema:      reportSchema,
		GeneratedAt: now,
		Summary:     summarize(findings),
		Findings:    findings,
		Probes:      outcomes,
		redactor:    red,
	}
}

// summarize computes the summary verdict over findings.
func summarize(findings []Finding) ReportSummary {
	counts := make(map[Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	worst := worstSeverity(findings)
	return ReportSummary{
		OK:               worst < SeverityWarning,
		WorstSeverity:    worst,
		TotalFindings:    len(findings),
		CountsBySeverity: counts,
	}
}

// Wire structs control exactly what is serialised and carry only redaction-safe
// shapes (strings and numbers).
type reportWire struct {
	Schema      string        `json:"schema"`
	GeneratedAt string        `json:"generated_at"`
	Summary     summaryWire   `json:"summary"`
	Findings    []findingWire `json:"findings"`
	Probes      []probeWire   `json:"probes"`
}

type summaryWire struct {
	OK               bool           `json:"ok"`
	WorstSeverity    Severity       `json:"worst_severity"`
	TotalFindings    int            `json:"total_findings"`
	CountsBySeverity map[string]int `json:"counts_by_severity"`
}

type findingWire struct {
	Code     Code              `json:"code"`
	Severity Severity          `json:"severity"`
	Probe    ProbeID           `json:"probe"`
	Summary  string            `json:"summary"`
	Evidence map[string]string `json:"evidence,omitempty"`
}

type probeWire struct {
	Probe      ProbeID     `json:"probe"`
	Status     ProbeStatus `json:"status"`
	DurationMS int64       `json:"duration_ms"`
	Findings   int         `json:"findings"`
}

// MarshalJSON renders the report and then passes the bytes through the run's
// redactor as a final, guaranteed scrub. Because this is the only path to the
// report's JSON, a raw secret cannot appear in the output even if a probe put
// one in a finding.
func (r Report) MarshalJSON() ([]byte, error) {
	w := reportWire{
		Schema:      r.Schema,
		GeneratedAt: r.GeneratedAt.UTC().Format(time.RFC3339),
		Summary: summaryWire{
			OK:               r.Summary.OK,
			WorstSeverity:    r.Summary.WorstSeverity,
			TotalFindings:    r.Summary.TotalFindings,
			CountsBySeverity: countsByName(r.Summary.CountsBySeverity),
		},
	}
	for _, f := range r.Findings {
		w.Findings = append(w.Findings, findingWire(f))
	}
	for _, p := range r.Probes {
		w.Probes = append(w.Probes, probeWire{
			Probe:      p.Probe,
			Status:     p.Status,
			DurationMS: p.Duration.Milliseconds(),
			Findings:   p.FindingCount,
		})
	}

	raw, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	red := r.redactor
	if red == nil {
		// A report built by hand has no run redactor; still apply pattern-based
		// scrubbing so the no-raw-secrets guarantee holds unconditionally.
		red = NewRedactor(nil)
	}
	return red.RedactJSON(raw)
}

// countsByName converts a severity-keyed count map into a name-keyed one for
// stable JSON output.
func countsByName(in map[Severity]int) map[string]int {
	out := make(map[string]int, len(in))
	for sev, n := range in {
		out[sev.String()] = n
	}
	return out
}

// Package report validates, evaluates, and renders package inspection evidence.
package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

const maxReportBytes = 2 * 1024 * 1024

// Validator applies the versioned JSON Schema before typed report decoding.
type Validator struct {
	schema *jsonschema.Schema
}

// NewValidator compiles a report schema from a trusted local file.
//
// The schema is loaded once at controller startup. This avoids accepting a
// schema or schema URI from the untrusted MicroVM response.
func NewValidator(schemaPath string) (*Validator, error) {
	compiler := jsonschema.NewCompiler()
	schemaFile, err := os.Open(schemaPath)
	if err != nil {
		return nil, fmt.Errorf("open report schema: %w", err)
	}
	defer schemaFile.Close()
	if err := compiler.AddResource("report.schema.json", schemaFile); err != nil {
		return nil, fmt.Errorf("add report schema: %w", err)
	}
	schema, err := compiler.Compile("report.schema.json")
	if err != nil {
		return nil, fmt.Errorf("compile report schema: %w", err)
	}
	return &Validator{schema: schema}, nil
}

// Decode validates a bounded JSON document and returns its typed projection.
func (validator *Validator) Decode(document []byte) (*Report, error) {
	if len(document) == 0 || len(document) > maxReportBytes {
		return nil, fmt.Errorf("report size must be between 1 and %d bytes", maxReportBytes)
	}
	var value interface{}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode report JSON: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("decode report JSON: trailing content is not allowed")
	}
	if err := validator.schema.Validate(value); err != nil {
		return nil, fmt.Errorf("validate report schema: %w", err)
	}
	var parsed Report
	strict := json.NewDecoder(bytes.NewReader(document))
	if err := strict.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode typed report: %w", err)
	}
	return &parsed, nil
}

// SHA256 returns the lowercase content digest stored in Kubernetes status.
func SHA256(document []byte) string {
	digest := sha256.Sum256(document)
	return hex.EncodeToString(digest[:])
}

// Report is the evidence subset consumed by deterministic policy rules.
type Report struct {
	SchemaVersion   string          `json:"schemaVersion"`
	Scan            Scan            `json:"scan"`
	Subject         Subject         `json:"subject"`
	Artifact        Artifact        `json:"artifact"`
	StaticAnalysis  StaticAnalysis  `json:"staticAnalysis"`
	DynamicAnalysis DynamicAnalysis `json:"dynamicAnalysis"`
	Execution       Execution       `json:"execution"`
}

// Scan identifies one immutable inspection attempt.
type Scan struct {
	ID            string `json:"id"`
	StartedAt     string `json:"startedAt"`
	FinishedAt    string `json:"finishedAt"`
	PolicyVersion string `json:"policyVersion"`
}

// Subject identifies the package observed by the runner.
type Subject struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

// Artifact contains integrity evidence for the inspected tarball.
type Artifact struct {
	SHA256            string `json:"sha256"`
	SizeBytes         int64  `json:"sizeBytes"`
	IntegrityVerified bool   `json:"integrityVerified"`
}

// StaticAnalysis contains package metadata and heuristic pattern matches.
type StaticAnalysis struct {
	LifecycleScripts   map[string]string `json:"lifecycleScripts"`
	DirectDependencies map[string]string `json:"directDependencies"`
	License            *string           `json:"license"`
	Patterns           []Pattern         `json:"patterns"`
	ArchiveWarnings    []string          `json:"archiveWarnings"`
}

// Pattern identifies a heuristic source-code match, not a vulnerability verdict.
type Pattern struct {
	RuleID string `json:"ruleId"`
	Path   string `json:"path"`
}

// Event is the normalized projection shared by dynamic evidence categories.
type Event struct {
	EventID                string `json:"eventId"`
	Type                   string `json:"type"`
	EvidenceType           string `json:"evidenceType"`
	CanaryType             string `json:"canaryType,omitempty"`
	Path                   string `json:"path,omitempty"`
	Executable             string `json:"executable,omitempty"`
	ArgumentsRaw           string `json:"argumentsRaw,omitempty"`
	CredentialPathCategory string `json:"credentialPathCategory,omitempty"`
}

// DynamicAnalysis groups bounded observations from strace and the demo canary.
type DynamicAnalysis struct {
	Filesystem       []Event   `json:"filesystem"`
	Processes        []Event   `json:"processes"`
	FileAccesses     []Event   `json:"fileAccesses"`
	DNS              []Event   `json:"dns"`
	Network          []Event   `json:"network"`
	EnvironmentReads []Event   `json:"environmentReads"`
	Resources        Resources `json:"resources"`
}

// Resources records coarse execution consumption and observer availability.
type Resources struct {
	WallTimeMS     int64 `json:"wallTimeMs"`
	PeakRSSBytes   int64 `json:"peakRssBytes"`
	TraceAvailable bool  `json:"traceAvailable"`
}

// Execution records the installer outcome without changing scan success semantics.
type Execution struct {
	Outcome              string `json:"outcome"`
	TimedOut             bool   `json:"timedOut"`
	KilledForOutputLimit bool   `json:"killedForOutputLimit"`
}

// Assessment is a deterministic policy result suitable for status and Markdown.
type Assessment struct {
	Score    int
	Level    string
	Findings []Finding
}

// Finding explains one stable policy rule and its additive score.
type Finding struct {
	ID       string
	Weight   int
	Evidence int
	Summary  string
}

// Evaluate applies demo policy npm-demo-v1 without invoking an LLM.
func Evaluate(report *Report) Assessment {
	findings := make([]Finding, 0, 10)
	add := func(id string, weight int, evidence int, summary string) {
		if evidence > 0 {
			findings = append(findings, Finding{id, weight, evidence, summary})
		}
	}

	if !report.Artifact.IntegrityVerified {
		add("artifact.integrity-unverified", 100, 1, "Artifact integrity was not verified")
	}
	add("npm.lifecycle-script", 15, len(report.StaticAnalysis.LifecycleScripts), "Package declares npm lifecycle scripts")
	add("static.suspicious-pattern", 10, len(report.StaticAnalysis.Patterns), "Static heuristics matched sensitive APIs or paths")
	add("archive.warning", 20, len(report.StaticAnalysis.ArchiveWarnings), "Archive contains unusual or unsafe entries")
	add("dynamic.child-process", 10, packageProcessEvents(report.DynamicAnalysis.Processes), "Installation created or executed child processes")
	add("dynamic.credential-path", 25, credentialEvents(report.DynamicAnalysis.FileAccesses), "A known credential path was opened or attempted")
	add("dynamic.dns", 10, len(report.DynamicAnalysis.DNS), "Installation attempted DNS resolution")
	add("dynamic.network", 20, len(report.DynamicAnalysis.Network), "Installation attempted an outbound network connection")
	add("dynamic.environment-read", 5, len(report.DynamicAnalysis.EnvironmentReads), "Canary observed an environment lookup")
	add("execution.timeout", 20, boolCount(report.Execution.TimedOut), "Installation exceeded its wall-clock limit")
	add("execution.output-limit", 20, boolCount(report.Execution.KilledForOutputLimit), "Installation exceeded its output limit")

	score := 0
	for _, finding := range findings {
		score += finding.Weight
	}
	if score > 100 {
		score = 100
	}
	return Assessment{Score: score, Level: level(score), Findings: findings}
}

// packageProcessEvents excludes the two deterministic process executions that
// launch every inspection. The events remain in the JSON evidence; only the
// risk calculation ignores trusted harness startup noise.
func packageProcessEvents(events []Event) int {
	count := 0
	for _, event := range events {
		if isHarnessProcess(event) {
			continue
		}
		count++
	}
	return count
}

// isHarnessProcess recognizes exact commands baked into the versioned runner
// image. Keeping this allowlist narrow avoids hiding unrelated child processes.
func isHarnessProcess(event Event) bool {
	if event.Type != "process-exec" || event.EvidenceType != "strace" {
		return false
	}
	if event.Executable == "/usr/bin/python3" {
		return strings.Contains(event.ArgumentsRaw, `"-m", "package_inspector.sandbox_exec"`)
	}
	if event.Executable == "/usr/local/bin/node" {
		return strings.Contains(event.ArgumentsRaw, `"/usr/local/bin/npm", "install"`) &&
			strings.Contains(event.ArgumentsRaw, `"--offline"`)
	}
	return false
}

// FindingIDs returns stable ordered identifiers for compact Kubernetes status.
func (assessment Assessment) FindingIDs() []string {
	identifiers := make([]string, 0, len(assessment.Findings))
	for _, finding := range assessment.Findings {
		identifiers = append(identifiers, finding.ID)
	}
	sort.Strings(identifiers)
	return identifiers
}

// Markdown renders an evidence summary while excluding untrusted stdout/stderr.
func Markdown(report *Report, assessment Assessment, jsonURI string) []byte {
	var output strings.Builder
	fmt.Fprintf(&output, "# Package inspection: %s@%s\n\n", markdown(report.Subject.Name), markdown(report.Subject.Version))
	fmt.Fprintf(&output, "- Ecosystem: `%s`\n", markdown(report.Subject.Ecosystem))
	fmt.Fprintf(&output, "- Artifact SHA-256: `%s`\n", report.Artifact.SHA256)
	fmt.Fprintf(&output, "- Execution outcome: `%s`\n", markdown(report.Execution.Outcome))
	fmt.Fprintf(&output, "- Risk: **%s (%d/100)**\n", strings.ToUpper(assessment.Level), assessment.Score)
	fmt.Fprintf(&output, "- Machine report: `%s`\n\n", markdown(jsonURI))
	output.WriteString("## Findings\n\n")
	if len(assessment.Findings) == 0 {
		output.WriteString("No demo policy rules matched. This is not a guarantee of safety.\n")
	} else {
		for _, finding := range assessment.Findings {
			fmt.Fprintf(&output, "- `%s` (+%d): %s; evidence=%d\n", finding.ID, finding.Weight, finding.Summary, finding.Evidence)
		}
	}
	output.WriteString("\n## Evidence counts\n\n")
	fmt.Fprintf(&output, "- Lifecycle scripts: %d\n", len(report.StaticAnalysis.LifecycleScripts))
	fmt.Fprintf(&output, "- Static pattern matches: %d\n", len(report.StaticAnalysis.Patterns))
	fmt.Fprintf(&output, "- Filesystem changes: %d\n", len(report.DynamicAnalysis.Filesystem))
	fmt.Fprintf(&output, "- Process events: %d\n", len(report.DynamicAnalysis.Processes))
	fmt.Fprintf(&output, "- DNS events: %d\n", len(report.DynamicAnalysis.DNS))
	fmt.Fprintf(&output, "- Network events: %d\n", len(report.DynamicAnalysis.Network))
	fmt.Fprintf(&output, "- strace available: %t\n", report.DynamicAnalysis.Resources.TraceAvailable)
	output.WriteString("\n> This technical demo reports bounded observations. It is not a malware analysis service and does not prove a package is safe.\n")
	return []byte(output.String())
}

// credentialEvents excludes npm's expected config lookup from sensitive-path rules.
func credentialEvents(events []Event) int {
	count := 0
	for _, event := range events {
		if (event.CredentialPathCategory != "" && event.CredentialPathCategory != "npm-credentials") || event.CanaryType == "credential-path-open" {
			count++
		}
	}
	return count
}

// boolCount converts one terminal boolean into an evidence count.
func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

// level maps a capped numeric score to stable article-friendly bands.
func level(score int) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 40:
		return "high"
	case score >= 20:
		return "medium"
	default:
		return "low"
	}
}

// markdown escapes inline code delimiters and removes line injection characters.
func markdown(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "`", "\\`", "\n", " ", "\r", " ")
	return replacer.Replace(value)
}

package report

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// TestEvaluateGoodReport verifies that absence of evidence remains low risk.
func TestEvaluateGoodReport(t *testing.T) {
	t.Parallel()
	report := &Report{Artifact: Artifact{IntegrityVerified: true}}

	assessment := Evaluate(report)

	if assessment.Score != 0 || assessment.Level != "low" || len(assessment.Findings) != 0 {
		t.Fatalf("unexpected good assessment: %#v", assessment)
	}
}

// TestValidatorAcceptsVersionOneContract verifies the Go consumer against the shared schema.
func TestValidatorAcceptsVersionOneContract(t *testing.T) {
	t.Parallel()
	validator, err := NewValidator(filepath.Join("..", "..", "..", "api", "report-schema", "report.schema.json"))
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	document, err := json.Marshal(minimalReportDocument())
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}

	parsed, err := validator.Decode(document)
	if err != nil {
		t.Fatalf("expected valid report: %v", err)
	}
	if parsed.Subject.Name != "@demo/good" || parsed.Scan.ID != "scan-1" {
		t.Fatalf("unexpected typed projection: %#v", parsed)
	}
}

// TestEvaluateCanaryReport verifies stable additive policy rules and score capping.
func TestEvaluateCanaryReport(t *testing.T) {
	t.Parallel()
	report := &Report{
		Artifact: Artifact{IntegrityVerified: true},
		StaticAnalysis: StaticAnalysis{
			LifecycleScripts: map[string]string{"postinstall": "node postinstall.js"},
			Patterns:         []Pattern{{RuleID: "network-api"}},
		},
		DynamicAnalysis: DynamicAnalysis{
			Processes:        []Event{{CanaryType: "child-process"}},
			FileAccesses:     []Event{{CanaryType: "credential-path-open"}},
			DNS:              []Event{{CanaryType: "dns-attempt"}},
			Network:          []Event{{CanaryType: "http-result"}},
			EnvironmentReads: []Event{{CanaryType: "environment-read"}},
		},
	}

	assessment := Evaluate(report)

	if assessment.Score != 95 || assessment.Level != "critical" {
		t.Fatalf("unexpected canary assessment: %#v", assessment)
	}
	if len(assessment.FindingIDs()) != 7 {
		t.Fatalf("expected seven findings, got %v", assessment.FindingIDs())
	}
}

// TestValidatorRejectsIncompleteReport verifies schema validation precedes policy.
func TestValidatorRejectsIncompleteReport(t *testing.T) {
	t.Parallel()
	schemaPath := filepath.Join("..", "..", "..", "api", "report-schema", "report.schema.json")
	validator, err := NewValidator(schemaPath)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}

	if _, err := validator.Decode([]byte(`{"schemaVersion":"1.0.0"}`)); err == nil {
		t.Fatal("expected an incomplete report to be rejected")
	}
}

// TestValidatorRejectsTrailingJSON verifies only one complete report is accepted.
func TestValidatorRejectsTrailingJSON(t *testing.T) {
	t.Parallel()
	validator, err := NewValidator(filepath.Join("..", "..", "..", "api", "report-schema", "report.schema.json"))
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	document, err := json.Marshal(minimalReportDocument())
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	document = append(document, []byte(` {"ignored":true}`)...)

	if _, err := validator.Decode(document); err == nil {
		t.Fatal("expected trailing JSON to be rejected")
	}
}

// TestMarkdownExcludesRawOutput verifies rendering cannot reproduce runner logs.
func TestMarkdownExcludesRawOutput(t *testing.T) {
	t.Parallel()
	report := &Report{
		Subject:   Subject{Ecosystem: "npm", Name: "pkg`\n# injected", Version: "1.0.0"},
		Artifact:  Artifact{SHA256: strings.Repeat("a", 64)},
		Execution: Execution{Outcome: "succeeded"},
	}

	document := string(Markdown(report, Assessment{Level: "low"}, "s3://bucket/report.json"))

	if strings.Contains(document, "\n# injected") {
		t.Fatalf("untrusted Markdown was not escaped: %s", document)
	}
}

// minimalReportDocument creates a schema-complete report without dynamic evidence.
func minimalReportDocument() map[string]interface{} {
	captured := map[string]interface{}{
		"text": "", "capturedBytes": 0, "observedBytes": 0, "truncated": false,
		"capturedSHA256": strings.Repeat("0", 64),
	}
	return map[string]interface{}{
		"schemaVersion": "1.0.0",
		"scan": map[string]interface{}{
			"id": "scan-1", "startedAt": "2026-07-19T00:00:00Z", "finishedAt": "2026-07-19T00:00:01Z",
			"runnerVersion": "0.1.0", "policyVersion": "npm-demo-v1",
		},
		"subject": map[string]interface{}{"ecosystem": "npm", "name": "@demo/good", "version": "1.0.0"},
		"artifact": map[string]interface{}{
			"filename": "good.tgz", "sha256": strings.Repeat("a", 64), "sizeBytes": 1, "integrityVerified": true,
		},
		"environment": map[string]interface{}{
			"architecture": "arm64", "operatingSystem": "Linux", "pythonVersion": "3.11",
			"nodeVersion": "v24", "npmVersion": "11", "microvmImageVersion": "test",
		},
		"staticAnalysis": map[string]interface{}{
			"packageMetadata": map[string]interface{}{}, "files": []interface{}{},
			"lifecycleScripts": map[string]interface{}{}, "directDependencies": map[string]interface{}{},
			"license": "MIT", "patterns": []interface{}{}, "archiveWarnings": []interface{}{},
		},
		"dynamicAnalysis": map[string]interface{}{
			"filesystem": []interface{}{}, "processes": []interface{}{}, "fileAccesses": []interface{}{},
			"dns": []interface{}{}, "network": []interface{}{}, "environmentReads": []interface{}{},
			"resources": map[string]interface{}{},
			"output":    map[string]interface{}{"stdout": captured, "stderr": captured},
		},
		"sbom": map[string]interface{}{
			"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
			"metadata": map[string]interface{}{}, "components": []interface{}{},
		},
		"limits": map[string]interface{}{
			"timeoutSeconds": 30, "cpuSeconds": 30, "stdoutBytes": 65536, "stderrBytes": 65536, "processes": 64, "fileBytes": 1024,
		},
		"execution": map[string]interface{}{
			"outcome": "succeeded", "exitCode": 0, "timedOut": false,
			"killedForOutputLimit": false, "errors": []interface{}{},
		},
	}
}

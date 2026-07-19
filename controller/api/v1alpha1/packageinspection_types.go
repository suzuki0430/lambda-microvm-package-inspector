package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// PackageInspectionSpec declares one exact allowlisted package inspection.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="PackageInspection spec is immutable"
type PackageInspectionSpec struct {
	// Ecosystem is fixed to npm for the first demo iteration.
	// +kubebuilder:validation:Enum=npm
	Ecosystem string `json:"ecosystem"`
	// Package identifies the exact package coordinate sent to the isolated runner.
	Package PackageSubject `json:"package"`
	// TimeoutSeconds bounds package execution inside the MicroVM.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=300
	// +kubebuilder:default=90
	TimeoutSeconds int32 `json:"timeoutSeconds,omitempty"`
}

// PackageSubject is an exact immutable npm package coordinate.
type PackageSubject struct {
	// Name is an allowlisted npm package name.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=214
	// +kubebuilder:validation:Enum="@demo/good";"@demo/canary"
	Name string `json:"name"`
	// Version is an exact package version, never a range or tag.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Enum="1.0.0"
	Version string `json:"version"`
}

// PackageInspectionStatus summarizes orchestration without embedding raw evidence.
type PackageInspectionStatus struct {
	// ObservedGeneration is the spec generation reflected by this status.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Phase is a stable coarse-grained state for kubectl and automation.
	Phase string `json:"phase,omitempty"`
	// MicrovmName is the owned ACK resource name while cleanup is in progress.
	MicrovmName string `json:"microvmName,omitempty"`
	// RemoteScanID is opaque and contains no authentication material.
	RemoteScanID string `json:"remoteScanID,omitempty"`
	// Report contains durable report locations and integrity metadata.
	Report *ReportReference `json:"report,omitempty"`
	// Risk contains the deterministic rule-based decision.
	Risk *RiskSummary `json:"risk,omitempty"`
	// Conditions follow Kubernetes status conventions for terminal and retryable states.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ReportReference identifies immutable JSON and Markdown objects in S3.
type ReportReference struct {
	JSONURI     string `json:"jsonURI"`
	MarkdownURI string `json:"markdownURI"`
	SHA256      string `json:"sha256"`
}

// RiskSummary is a bounded non-AI assessment derived from report evidence.
type RiskSummary struct {
	Score        int32    `json:"score"`
	Level        string   `json:"level"`
	FindingIDs   []string `json:"findingIDs,omitempty"`
	FindingCount int32    `json:"findingCount"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Package",type=string,JSONPath=`.spec.package.name`
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.spec.package.version`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Risk",type=string,JSONPath=`.status.risk.level`

// PackageInspection requests one package run in one fresh Lambda MicroVM.
type PackageInspection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PackageInspectionSpec   `json:"spec"`
	Status PackageInspectionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PackageInspectionList contains PackageInspection resources.
type PackageInspectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PackageInspection `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PackageInspection{}, &PackageInspectionList{})
}

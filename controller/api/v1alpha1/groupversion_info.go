// Package v1alpha1 contains the Kubernetes API for package inspections.
// +kubebuilder:object:generate=true
// +groupName=inspection.demo.aws
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion identifies the demo API group and storage version.
	GroupVersion = schema.GroupVersion{Group: "inspection.demo.aws", Version: "v1alpha1"}
	// SchemeBuilder registers PackageInspection objects with a manager scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}
	// AddToScheme adds all API objects in this package to a runtime scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

package controller

import (
	"strings"
	"testing"

	inspectionv1alpha1 "github.com/example/lambda-microvm-package-inspector/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// TestDesiredMicrovmOmitsExecutionRole verifies the untrusted guest receives no AWS role.
func TestDesiredMicrovmOmitsExecutionRole(t *testing.T) {
	t.Parallel()
	reconciler := &PackageInspectionReconciler{
		ImageIdentifier:     "arn:aws:lambda:us-east-1:123456789012:microvm-image:inspector",
		EgressConnectorARN:  "arn:aws:lambda:us-east-1:123456789012:network-connector/deny",
		IngressConnectorARN: "arn:aws:lambda:us-east-1:aws:network-connector:aws-network-connector:ALL_INGRESS",
	}
	inspection := &inspectionv1alpha1.PackageInspection{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "default", UID: types.UID("uid-1")},
		Spec:       inspectionv1alpha1.PackageInspectionSpec{TimeoutSeconds: 30},
	}

	child := reconciler.desiredMicrovm(inspection)
	spec := child.Object["spec"].(map[string]interface{})

	if _, exists := spec["executionRoleARN"]; exists {
		t.Fatal("MicroVM must not receive an execution role")
	}
	if _, exists := spec["egressNetworkConnectors"]; !exists {
		t.Fatal("MicroVM must use the deny-by-default VPC connector")
	}
}

// TestChildNameIsBounded verifies long CR names create valid ACK resource names.
func TestChildNameIsBounded(t *testing.T) {
	t.Parallel()
	inspection := &inspectionv1alpha1.PackageInspection{ObjectMeta: metav1.ObjectMeta{Name: strings.Repeat("a", 200)}}

	name := childName(inspection)

	if len(name) > 63 || !strings.HasSuffix(name, "-mvm") {
		t.Fatalf("invalid child name %q", name)
	}
}

// TestValidateSpecRejectsBroadRequests verifies MVP admission remains narrow.
func TestValidateSpecRejectsBroadRequests(t *testing.T) {
	t.Parallel()
	spec := &inspectionv1alpha1.PackageInspectionSpec{
		Ecosystem: "pip",
		Package:   inspectionv1alpha1.PackageSubject{Name: "anything", Version: "latest"},
	}

	if err := validateSpec(spec); err == nil {
		t.Fatal("expected non-npm ecosystem rejection")
	}
}

// TestTerminalPhasePreventsReallocation verifies completed CRs remain terminal.
func TestTerminalPhasePreventsReallocation(t *testing.T) {
	t.Parallel()
	if !terminalPhase("Succeeded") || !terminalPhase("Failed") {
		t.Fatal("terminal phases must not allocate another MicroVM")
	}
	if terminalPhase("Cleaning") || terminalPhase("Provisioning") {
		t.Fatal("active phases must continue reconciliation")
	}
}

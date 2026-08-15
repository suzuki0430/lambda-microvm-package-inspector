// Package controller reconciles PackageInspection and owned ACK Microvm resources.
// +kubebuilder:rbac:groups=inspection.demo.aws,resources=packageinspections,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=inspection.demo.aws,resources=packageinspections/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=inspection.demo.aws,resources=packageinspections/finalizers,verbs=update
// +kubebuilder:rbac:groups=lambdamicrovms.services.k8s.aws,resources=microvms,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch
package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	inspectionv1alpha1 "github.com/example/lambda-microvm-package-inspector/controller/api/v1alpha1"
	inspectionreport "github.com/example/lambda-microvm-package-inspector/controller/internal/report"
	"github.com/example/lambda-microvm-package-inspector/controller/internal/runner"
	"github.com/example/lambda-microvm-package-inspector/controller/internal/store"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apiMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

const (
	inspectionFinalizer = "inspection.demo.aws/microvm-cleanup"
	resultCondition     = "Result"
	defaultTimeout      = int32(90)
)

var microvmGVK = schema.GroupVersionKind{
	Group: "lambdamicrovms.services.k8s.aws", Version: "v1alpha1", Kind: "Microvm",
}

// RunnerClient is the isolated runner protocol used by the reconciler.
type RunnerClient interface {
	Submit(context.Context, string, string, runner.ScanRequest) (string, error)
	Status(context.Context, string, string, string) (runner.ScanStatus, error)
	Report(context.Context, string, string, string) ([]byte, error)
}

// ReportStore persists completed bundles and derives stable S3 URIs.
type ReportStore interface {
	References(namespace, name, uid string) store.References
	Put(context.Context, string, string, string, string, []byte, []byte) (store.References, error)
}

// PackageInspectionReconciler maps one user CR to one disposable ACK Microvm.
type PackageInspectionReconciler struct {
	client.Client
	Runner              RunnerClient
	Validator           *inspectionreport.Validator
	Store               ReportStore
	Recorder            record.EventRecorder
	ImageIdentifier     string
	ImageVersion        string
	EgressConnectorARN  string
	IngressConnectorARN string
	PollInterval        time.Duration
}

// SetupWithManager registers a bounded-concurrency controller.
func (reconciler *PackageInspectionReconciler) SetupWithManager(manager ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(manager).
		For(&inspectionv1alpha1.PackageInspection{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(reconciler)
}

// Reconcile advances provisioning, inspection, storage, and cleanup idempotently.
func (reconciler *PackageInspectionReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	var inspection inspectionv1alpha1.PackageInspection
	if err := reconciler.Get(ctx, request.NamespacedName, &inspection); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !inspection.DeletionTimestamp.IsZero() {
		return reconciler.reconcileDeletion(ctx, &inspection)
	}
	if !contains(inspection.Finalizers, inspectionFinalizer) {
		inspection.Finalizers = append(inspection.Finalizers, inspectionFinalizer)
		if err := reconciler.Update(ctx, &inspection); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}
	if terminalPhase(inspection.Status.Phase) {
		return ctrl.Result{}, nil
	}
	if err := validateSpec(&inspection.Spec); err != nil {
		return reconciler.beginFailure(ctx, &inspection, "InvalidSpec", err)
	}

	child := microvmObject(inspection.Namespace, childName(&inspection))
	err := reconciler.Get(ctx, client.ObjectKeyFromObject(child), child)
	if apierrors.IsNotFound(err) {
		if inspection.Status.Phase == "Cleaning" {
			return reconciler.finishAfterCleanup(ctx, &inspection)
		}
		created := reconciler.desiredMicrovm(&inspection)
		if err := reconciler.Create(ctx, created); err != nil {
			return ctrl.Result{}, fmt.Errorf("create ACK Microvm: %w", err)
		}
		inspection.Status.MicrovmName = created.GetName()
		inspection.Status.Phase = "Provisioning"
		inspection.Status.ObservedGeneration = inspection.Generation
		reconciler.Recorder.Event(&inspection, "Normal", "MicrovmCreated", "Created isolated ACK Microvm resource")
		return reconciler.updateStatus(ctx, &inspection, true)
	}
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("get ACK Microvm: %w", err)
	}
	if inspection.Status.Phase == "Cleaning" {
		return reconciler.deleteChild(ctx, child)
	}
	if ackTerminal(child) {
		return reconciler.beginFailure(ctx, &inspection, "ACKTerminal", fmt.Errorf("ACK reported a terminal resource condition"))
	}

	state, _, _ := unstructured.NestedString(child.Object, "status", "state")
	switch state {
	case "":
		return reconciler.requeue(), nil
	case "PENDING":
		return reconciler.requeue(), nil
	case "RUNNING":
		return reconciler.reconcileRunning(ctx, &inspection, child)
	case "TERMINATED":
		return reconciler.beginFailure(ctx, &inspection, "MicrovmTerminated", fmt.Errorf("MicroVM terminated before report storage"))
	default:
		return reconciler.requeue(), nil
	}
}

// terminalPhase reports whether an inspection must never allocate another MicroVM.
func terminalPhase(phase string) bool {
	return phase == "Succeeded" || phase == "Failed"
}

// reconcileRunning submits once, then polls the asynchronous runner state.
func (reconciler *PackageInspectionReconciler) reconcileRunning(ctx context.Context, inspection *inspectionv1alpha1.PackageInspection, child *unstructured.Unstructured) (ctrl.Result, error) {
	microvmID, _, _ := unstructured.NestedString(child.Object, "status", "microvmID")
	endpoint, _, _ := unstructured.NestedString(child.Object, "status", "endpoint")
	if microvmID == "" || endpoint == "" {
		return reconciler.requeue(), nil
	}
	scanID := string(inspection.UID)
	if inspection.Status.RemoteScanID == "" {
		acceptedID, err := reconciler.Runner.Submit(ctx, endpoint, microvmID, runner.ScanRequest{
			ScanID:         scanID,
			Ecosystem:      inspection.Spec.Ecosystem,
			Package:        runner.PackageSubject{Name: inspection.Spec.Package.Name, Version: inspection.Spec.Package.Version},
			TimeoutSeconds: effectiveTimeout(inspection.Spec.TimeoutSeconds),
		})
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("submit isolated scan: %w", err)
		}
		if acceptedID != scanID {
			return reconciler.beginFailure(ctx, inspection, "RunnerProtocolError", fmt.Errorf("runner changed deterministic scan ID"))
		}
		inspection.Status.RemoteScanID = acceptedID
		inspection.Status.Phase = "Inspecting"
		reconciler.Recorder.Event(inspection, "Normal", "InspectionStarted", "Package installation started inside isolated MicroVM")
		return reconciler.updateStatus(ctx, inspection, true)
	}

	status, err := reconciler.Runner.Status(ctx, endpoint, microvmID, inspection.Status.RemoteScanID)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("poll isolated scan: %w", err)
	}
	switch status.State {
	case "accepted", "inspecting":
		return reconciler.requeue(), nil
	case "failed":
		return reconciler.beginFailure(ctx, inspection, "RunnerFailed", fmt.Errorf("isolated runner failed"))
	case "completed":
		return reconciler.collectReport(ctx, inspection, endpoint, microvmID)
	default:
		return reconciler.beginFailure(ctx, inspection, "RunnerProtocolError", fmt.Errorf("runner returned unknown state"))
	}
}

// collectReport validates identity and schema before policy evaluation and S3 writes.
func (reconciler *PackageInspectionReconciler) collectReport(ctx context.Context, inspection *inspectionv1alpha1.PackageInspection, endpoint, microvmID string) (ctrl.Result, error) {
	document, err := reconciler.Runner.Report(ctx, endpoint, microvmID, inspection.Status.RemoteScanID)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("download isolated report: %w", err)
	}
	parsed, err := reconciler.Validator.Decode(document)
	if err != nil {
		return reconciler.beginFailure(ctx, inspection, "InvalidReport", err)
	}
	if parsed.Scan.ID != inspection.Status.RemoteScanID || parsed.Subject.Ecosystem != inspection.Spec.Ecosystem ||
		parsed.Subject.Name != inspection.Spec.Package.Name || parsed.Subject.Version != inspection.Spec.Package.Version {
		return reconciler.beginFailure(ctx, inspection, "ReportIdentityMismatch", fmt.Errorf("report identity differs from request"))
	}
	if parsed.Scan.PolicyVersion != "npm-demo-v1" {
		return reconciler.beginFailure(ctx, inspection, "ReportPolicyMismatch", fmt.Errorf("report policy version is unsupported"))
	}
	digest := inspectionreport.SHA256(document)
	assessment := inspectionreport.Evaluate(parsed)
	uid := string(inspection.UID)
	planned := reconciler.Store.References(inspection.Namespace, inspection.Name, uid)
	markdown := inspectionreport.Markdown(parsed, assessment, planned.JSONURI)
	references, err := reconciler.Store.Put(ctx, inspection.Namespace, inspection.Name, uid, digest, document, markdown)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("store validated report: %w", err)
	}
	inspection.Status.Report = &inspectionv1alpha1.ReportReference{
		JSONURI: references.JSONURI, MarkdownURI: references.MarkdownURI, SHA256: digest,
	}
	inspection.Status.Risk = &inspectionv1alpha1.RiskSummary{
		Score: int32(assessment.Score), Level: assessment.Level,
		FindingIDs: assessment.FindingIDs(), FindingCount: int32(len(assessment.Findings)),
	}
	inspection.Status.Phase = "Cleaning"
	apiMeta.SetStatusCondition(&inspection.Status.Conditions, metav1.Condition{
		Type: resultCondition, Status: metav1.ConditionTrue, Reason: "ReportStored",
		Message: "Validated reports stored; waiting for MicroVM termination", ObservedGeneration: inspection.Generation,
	})
	reconciler.Recorder.Event(inspection, "Normal", "ReportStored", "Validated JSON and Markdown reports stored in S3")
	return reconciler.updateStatus(ctx, inspection, true)
}

// beginFailure records a redacted terminal result and always enters cleanup first.
func (reconciler *PackageInspectionReconciler) beginFailure(ctx context.Context, inspection *inspectionv1alpha1.PackageInspection, reason string, cause error) (ctrl.Result, error) {
	ctrl.LoggerFrom(ctx).Info(
		"inspection workflow failed",
		"reason", reason,
		"failureType", fmt.Sprintf("%T", cause),
	)
	inspection.Status.Phase = "Cleaning"
	apiMeta.SetStatusCondition(&inspection.Status.Conditions, metav1.Condition{
		Type: resultCondition, Status: metav1.ConditionFalse, Reason: reason,
		Message: "Inspection failed; controller is deleting the MicroVM. See controller logs for details.", ObservedGeneration: inspection.Generation,
	})
	reconciler.Recorder.Event(inspection, "Warning", reason, "Inspection failed; cleaning up isolated MicroVM")
	return reconciler.updateStatus(ctx, inspection, true)
}

// finishAfterCleanup publishes success or failure only after the ACK child is absent.
func (reconciler *PackageInspectionReconciler) finishAfterCleanup(ctx context.Context, inspection *inspectionv1alpha1.PackageInspection) (ctrl.Result, error) {
	condition := apiMeta.FindStatusCondition(inspection.Status.Conditions, resultCondition)
	if condition != nil && condition.Status == metav1.ConditionTrue {
		inspection.Status.Phase = "Succeeded"
		condition.Message = "Validated reports stored and isolated MicroVM cleanup confirmed."
	} else {
		inspection.Status.Phase = "Failed"
		if condition != nil {
			condition.Message = "Inspection failed and isolated MicroVM cleanup was confirmed."
		}
	}
	inspection.Status.MicrovmName = ""
	reconciler.Recorder.Event(inspection, "Normal", "MicrovmDeleted", "Confirmed isolated MicroVM cleanup")
	return reconciler.updateStatus(ctx, inspection, false)
}

// reconcileDeletion removes the owned MicroVM before releasing the parent finalizer.
func (reconciler *PackageInspectionReconciler) reconcileDeletion(ctx context.Context, inspection *inspectionv1alpha1.PackageInspection) (ctrl.Result, error) {
	if !contains(inspection.Finalizers, inspectionFinalizer) {
		return ctrl.Result{}, nil
	}
	child := microvmObject(inspection.Namespace, childName(inspection))
	err := reconciler.Get(ctx, client.ObjectKeyFromObject(child), child)
	if err == nil {
		return reconciler.deleteChild(ctx, child)
	}
	if !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}
	inspection.Finalizers = remove(inspection.Finalizers, inspectionFinalizer)
	return ctrl.Result{}, reconciler.Update(ctx, inspection)
}

// deleteChild requests ACK deletion once and then waits for finalizer completion.
func (reconciler *PackageInspectionReconciler) deleteChild(ctx context.Context, child *unstructured.Unstructured) (ctrl.Result, error) {
	if child.GetDeletionTimestamp().IsZero() {
		if err := reconciler.Delete(ctx, child); client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, fmt.Errorf("delete ACK Microvm: %w", err)
		}
	}
	return reconciler.requeue(), nil
}

// desiredMicrovm builds the narrow ACK CR without an execution role or shell access.
func (reconciler *PackageInspectionReconciler) desiredMicrovm(inspection *inspectionv1alpha1.PackageInspection) *unstructured.Unstructured {
	child := microvmObject(inspection.Namespace, childName(inspection))
	child.SetLabels(map[string]string{"app.kubernetes.io/managed-by": "package-inspection-controller"})
	child.SetOwnerReferences([]metav1.OwnerReference{{
		APIVersion: inspectionv1alpha1.GroupVersion.String(), Kind: "PackageInspection",
		Name: inspection.Name, UID: inspection.UID, Controller: pointer(true), BlockOwnerDeletion: pointer(true),
	}})
	spec := map[string]interface{}{
		"imageIdentifier":          reconciler.ImageIdentifier,
		"ingressNetworkConnectors": []interface{}{reconciler.IngressConnectorARN},
		"egressNetworkConnectors":  []interface{}{reconciler.EgressConnectorARN},
		"maximumDurationInSeconds": int64(effectiveTimeout(inspection.Spec.TimeoutSeconds) + 120),
		"logging":                  map[string]interface{}{"disabled": map[string]interface{}{}},
	}
	if reconciler.ImageVersion != "" {
		spec["imageVersion"] = reconciler.ImageVersion
	}
	child.Object["spec"] = spec
	return child
}

// updateStatus persists observed state before scheduling another reconciliation.
func (reconciler *PackageInspectionReconciler) updateStatus(ctx context.Context, inspection *inspectionv1alpha1.PackageInspection, requeue bool) (ctrl.Result, error) {
	inspection.Status.ObservedGeneration = inspection.Generation
	if err := reconciler.Status().Update(ctx, inspection); err != nil {
		return ctrl.Result{}, err
	}
	if requeue {
		return reconciler.requeue(), nil
	}
	return ctrl.Result{}, nil
}

// requeue returns the configured bounded polling interval.
func (reconciler *PackageInspectionReconciler) requeue() ctrl.Result {
	interval := reconciler.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return ctrl.Result{RequeueAfter: interval}
}

// validateSpec enforces the two-fixture MVP boundary even without admission webhooks.
func validateSpec(spec *inspectionv1alpha1.PackageInspectionSpec) error {
	if spec.Ecosystem != "npm" {
		return fmt.Errorf("only npm is supported")
	}
	if spec.Package.Name == "" || len(spec.Package.Name) > 214 || strings.ContainsAny(spec.Package.Name, "\x00\r\n") {
		return fmt.Errorf("package name is invalid")
	}
	if spec.Package.Version == "" || len(spec.Package.Version) > 128 {
		return fmt.Errorf("package version is invalid")
	}
	if spec.Package.Version != "1.0.0" || (spec.Package.Name != "@demo/good" && spec.Package.Name != "@demo/canary") {
		return fmt.Errorf("package is not in the MVP fixture allowlist")
	}
	if timeout := effectiveTimeout(spec.TimeoutSeconds); timeout < 1 || timeout > 300 {
		return fmt.Errorf("timeoutSeconds must be between 1 and 300")
	}
	return nil
}

// effectiveTimeout applies the CRD default defensively for direct API clients.
func effectiveTimeout(timeout int32) int32 {
	if timeout == 0 {
		return defaultTimeout
	}
	return timeout
}

// childName derives a DNS-safe bounded ACK resource name deterministically.
func childName(inspection *inspectionv1alpha1.PackageInspection) string {
	if len(inspection.Name) <= 59 {
		return inspection.Name + "-mvm"
	}
	digest := sha256.Sum256([]byte(inspection.Name))
	return inspection.Name[:50] + "-" + hex.EncodeToString(digest[:4]) + "-mvm"
}

// microvmObject creates an identity-only object for dynamic ACK interactions.
func microvmObject(namespace, name string) *unstructured.Unstructured {
	object := &unstructured.Unstructured{}
	object.SetGroupVersionKind(microvmGVK)
	object.SetNamespace(namespace)
	object.SetName(name)
	return object
}

// contains reports whether a Kubernetes finalizer slice contains one value.
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// remove returns the finalizer slice without the requested value.
func remove(values []string, unwanted string) []string {
	result := values[:0]
	for _, value := range values {
		if value != unwanted {
			result = append(result, value)
		}
	}
	return result
}

// pointer returns an address for Kubernetes owner-reference boolean fields.
func pointer[T any](value T) *T { return &value }

// ackTerminal detects ACK's non-retryable backend failure condition.
func ackTerminal(child *unstructured.Unstructured) bool {
	conditions, _, _ := unstructured.NestedSlice(child.Object, "status", "conditions")
	for _, raw := range conditions {
		condition, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if condition["type"] == "ACK.Terminal" && condition["status"] == "True" {
			return true
		}
	}
	return false
}

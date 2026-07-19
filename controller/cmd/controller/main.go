// Command controller runs the PackageInspection Kubernetes control plane.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/lambdamicrovms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	inspectionv1alpha1 "github.com/example/lambda-microvm-package-inspector/controller/api/v1alpha1"
	inspectioncontroller "github.com/example/lambda-microvm-package-inspector/controller/internal/controller"
	inspectionreport "github.com/example/lambda-microvm-package-inspector/controller/internal/report"
	"github.com/example/lambda-microvm-package-inspector/controller/internal/runner"
	"github.com/example/lambda-microvm-package-inspector/controller/internal/store"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// main validates all safety-critical settings before starting any reconciler.
func main() {
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zap.Options{Development: false})))
	logger := ctrl.Log.WithName("startup")
	settings, err := loadSettings()
	if err != nil {
		logger.Error(err, "invalid controller configuration")
		os.Exit(1)
	}
	validator, err := inspectionreport.NewValidator(settings.reportSchemaPath)
	if err != nil {
		logger.Error(err, "load report schema")
		os.Exit(1)
	}
	awsConfig, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(settings.region))
	if err != nil {
		logger.Error(err, "load AWS SDK configuration")
		os.Exit(1)
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(inspectionv1alpha1.AddToScheme(scheme))
	manager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Cache: cache.Options{DefaultNamespaces: map[string]cache.Config{
			settings.namespace: {},
		}},
		LeaderElection:         true,
		LeaderElectionID:       "package-inspection-controller.inspection.demo.aws",
		HealthProbeBindAddress: ":8081",
		Metrics:                metricsserver.Options{BindAddress: ":8082"},
	})
	if err != nil {
		logger.Error(err, "create Kubernetes manager")
		os.Exit(1)
	}

	tokenProvider := runner.NewAWSTokenProvider(lambdamicrovms.NewFromConfig(awsConfig))
	runnerClient := runner.NewClient(tokenProvider, settings.region)
	reportStore := store.NewS3Store(s3.NewFromConfig(awsConfig), settings.reportBucket, settings.reportPrefix)
	reconciler := &inspectioncontroller.PackageInspectionReconciler{
		Client: manager.GetClient(), Runner: runnerClient, Validator: validator,
		Store: reportStore, Recorder: manager.GetEventRecorderFor("package-inspection-controller"),
		ImageIdentifier: settings.imageIdentifier, ImageVersion: settings.imageVersion,
		EgressConnectorARN: settings.egressConnectorARN, IngressConnectorARN: settings.ingressConnectorARN,
		PollInterval: 2 * time.Second,
	}
	if err := reconciler.SetupWithManager(manager); err != nil {
		logger.Error(err, "register PackageInspection reconciler")
		os.Exit(1)
	}
	if err := manager.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		logger.Error(err, "register health check")
		os.Exit(1)
	}
	if err := manager.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		logger.Error(err, "register readiness check")
		os.Exit(1)
	}
	logger.Info("starting controller", "region", settings.region)
	if err := manager.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error(err, "controller stopped")
		os.Exit(1)
	}
}

// settings contains immutable process configuration sourced from the Deployment.
type settings struct {
	region              string
	imageIdentifier     string
	imageVersion        string
	egressConnectorARN  string
	ingressConnectorARN string
	reportBucket        string
	reportPrefix        string
	reportSchemaPath    string
	namespace           string
}

// loadSettings reads environment variables and rejects missing isolation controls.
func loadSettings() (settings, error) {
	result := settings{
		region: os.Getenv("AWS_REGION"), imageIdentifier: os.Getenv("INSPECTOR_IMAGE_IDENTIFIER"),
		imageVersion: os.Getenv("INSPECTOR_IMAGE_VERSION"), egressConnectorARN: os.Getenv("INSPECTOR_EGRESS_CONNECTOR_ARN"),
		reportBucket: os.Getenv("REPORT_BUCKET"), reportPrefix: valueOrDefault("REPORT_PREFIX", "reports"),
		reportSchemaPath: valueOrDefault("REPORT_SCHEMA_PATH", "/etc/package-inspector/report.schema.json"),
		namespace:        valueOrDefault("WATCH_NAMESPACE", "package-inspector-system"),
	}
	if result.region == "" || result.imageIdentifier == "" || result.egressConnectorARN == "" || result.reportBucket == "" {
		return settings{}, fmt.Errorf("AWS_REGION, INSPECTOR_IMAGE_IDENTIFIER, INSPECTOR_EGRESS_CONNECTOR_ARN, and REPORT_BUCKET are required")
	}
	result.ingressConnectorARN = valueOrDefault(
		"INSPECTOR_INGRESS_CONNECTOR_ARN",
		fmt.Sprintf("arn:aws:lambda:%s:aws:network-connector:aws-network-connector:ALL_INGRESS", result.region),
	)
	return result, nil
}

// valueOrDefault returns one non-empty environment value or its documented default.
func valueOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

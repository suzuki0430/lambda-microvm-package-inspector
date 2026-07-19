package runner

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"
)

type staticTokenProvider struct{}

// CreateToken returns a non-secret test token without making an AWS call.
func (staticTokenProvider) CreateToken(_ context.Context, _ string, _ int32) (string, error) {
	return "test-token", nil
}

// TestEndpointAcceptsExpectedAWSOrigin verifies the ACK endpoint shape is allowed.
func TestEndpointAcceptsExpectedAWSOrigin(t *testing.T) {
	t.Parallel()
	client := NewClient(staticTokenProvider{}, "us-east-1")

	endpoint, err := client.endpoint("mvm-123.lambda-microvm.us-east-1.on.aws")
	if err != nil {
		t.Fatalf("expected endpoint to pass: %v", err)
	}
	if endpoint.Scheme != "https" {
		t.Fatalf("expected forced HTTPS, got %s", endpoint.Scheme)
	}
}

// TestClientTransportRejectsAmbientProxying verifies JWE headers stay direct.
func TestClientTransportRejectsAmbientProxying(t *testing.T) {
	t.Parallel()
	client := NewClient(staticTokenProvider{}, "us-east-1")
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected a dedicated HTTP transport")
	}
	if transport.Proxy != nil || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("transport must disable ambient proxies and require TLS 1.2 or newer")
	}
}

// TestEndpointRejectsSSRFOrigins verifies status data cannot redirect the controller.
func TestEndpointRejectsSSRFOrigins(t *testing.T) {
	t.Parallel()
	client := NewClient(staticTokenProvider{}, "us-east-1")
	invalid := []string{
		"http://mvm-123.lambda-microvm.us-east-1.on.aws",
		"https://127.0.0.1",
		"https://mvm-123.lambda-microvm.eu-west-1.on.aws",
		"https://mvm-123.lambda-microvm.us-east-1.on.aws.evil.invalid",
		"https://mvm-123.lambda-microvm.us-east-1.on.aws:8443",
	}
	for _, value := range invalid {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, err := client.endpoint(value); err == nil {
				t.Fatalf("expected endpoint rejection: %s", value)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip implements http.RoundTripper for request-contract tests.
func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

// TestSubmitScopesHeadersAndAcceptsIdempotentState verifies the Lambda ingress contract.
func TestSubmitScopesHeadersAndAcceptsIdempotentState(t *testing.T) {
	t.Parallel()
	client := NewClient(staticTokenProvider{}, "us-east-1")
	client.httpClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("X-aws-proxy-auth") != "test-token" || request.Header.Get("X-aws-proxy-port") != "8080" {
			t.Fatalf("missing scoped Lambda headers: %#v", request.Header)
		}
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Body:       io.NopCloser(strings.NewReader(`{"scanId":"uid-1","state":"inspecting"}`)),
			Header:     make(http.Header),
		}, nil
	})

	scanID, err := client.Submit(context.Background(), "mvm.lambda-microvm.us-east-1.on.aws", "mvm-1", ScanRequest{
		ScanID: "uid-1", Ecosystem: "npm", Package: PackageSubject{Name: "@demo/good", Version: "1.0.0"}, TimeoutSeconds: 30,
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if scanID != "uid-1" {
		t.Fatalf("unexpected scan ID: %s", scanID)
	}
}

// TestSubmitDoesNotEchoRunnerErrors verifies untrusted bodies cannot enter logs.
func TestSubmitDoesNotEchoRunnerErrors(t *testing.T) {
	t.Parallel()
	client := NewClient(staticTokenProvider{}, "us-east-1")
	client.httpClient.Transport = roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader("do-not-log-this-value")),
			Header:     make(http.Header),
		}, nil
	})

	_, err := client.Submit(context.Background(), "mvm.lambda-microvm.us-east-1.on.aws", "mvm-1", ScanRequest{
		ScanID: "uid-1", Ecosystem: "npm", Package: PackageSubject{Name: "@demo/good", Version: "1.0.0"}, TimeoutSeconds: 30,
	})
	if err == nil || strings.Contains(err.Error(), "do-not-log-this-value") {
		t.Fatalf("expected redacted HTTP error, got %v", err)
	}
}

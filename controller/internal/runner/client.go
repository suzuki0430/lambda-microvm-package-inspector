// Package runner communicates with the untrusted inspector through Lambda ingress.
package runner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	runnerPort       = 8080
	maxResponseBytes = 2*1024*1024 + 1
)

// TokenProvider creates a short-lived token scoped to the runner port.
type TokenProvider interface {
	CreateToken(ctx context.Context, microvmID string, port int32) (string, error)
}

// Client sends bounded authenticated requests to one Lambda MicroVM endpoint.
type Client struct {
	tokens     TokenProvider
	httpClient *http.Client
	region     string
}

// NewClient constructs a runner client with explicit timeouts and region pinning.
func NewClient(tokens TokenProvider, region string) *Client {
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 16 * 1024,
		ResponseHeaderTimeout:  10 * time.Second,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    5 * time.Second,
	}
	return &Client{
		tokens: tokens,
		httpClient: &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return fmt.Errorf("MicroVM endpoint redirects are disabled")
			},
		},
		region: region,
	}
}

// Submit starts the MicroVM's one and only package inspection.
func (client *Client) Submit(ctx context.Context, endpoint, microvmID string, request ScanRequest) (string, error) {
	var response scanResponse
	if err := client.request(ctx, http.MethodPost, endpoint, microvmID, "/v1/scans", request, &response); err != nil {
		return "", err
	}
	if response.ScanID == "" || (response.State != "accepted" && response.State != "inspecting" && response.State != "completed") {
		return "", fmt.Errorf("runner returned an invalid acceptance response")
	}
	return response.ScanID, nil
}

// Status retrieves bounded progress without downloading the full report.
func (client *Client) Status(ctx context.Context, endpoint, microvmID, scanID string) (ScanStatus, error) {
	var response ScanStatus
	path := "/v1/scans/" + url.PathEscape(scanID)
	if err := client.request(ctx, http.MethodGet, endpoint, microvmID, path, nil, &response); err != nil {
		return ScanStatus{}, err
	}
	return response, nil
}

// Report downloads the completed raw report for schema validation and storage.
func (client *Client) Report(ctx context.Context, endpoint, microvmID, scanID string) ([]byte, error) {
	path := "/v1/scans/" + url.PathEscape(scanID) + "/report"
	return client.requestBytes(ctx, http.MethodGet, endpoint, microvmID, path, nil)
}

// ScanRequest is the intentionally narrow capability sent to an isolated runner.
type ScanRequest struct {
	ScanID         string         `json:"scanId"`
	Ecosystem      string         `json:"ecosystem"`
	Package        PackageSubject `json:"package"`
	TimeoutSeconds int32          `json:"timeoutSeconds"`
}

// PackageSubject identifies one exact artifact already present in the image catalog.
type PackageSubject struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ScanStatus is the bounded asynchronous state returned by the runner.
type ScanStatus struct {
	ScanID string `json:"scanId"`
	State  string `json:"state"`
	Error  string `json:"error,omitempty"`
}

type scanResponse struct {
	ScanID string `json:"scanId"`
	State  string `json:"state"`
}

// request performs a bounded request and decodes one JSON response object.
func (client *Client) request(ctx context.Context, method, endpoint, microvmID, path string, body interface{}, output interface{}) error {
	document, err := client.requestBytes(ctx, method, endpoint, microvmID, path, body)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode runner response: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("decode runner response: trailing content is not allowed")
	}
	return nil
}

// requestBytes obtains a fresh JWE and returns at most the report size limit.
func (client *Client) requestBytes(ctx context.Context, method, endpoint, microvmID, path string, body interface{}) ([]byte, error) {
	base, err := client.endpoint(endpoint)
	if err != nil {
		return nil, err
	}
	base.Path = path
	var payload io.Reader
	if body != nil {
		document, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			return nil, fmt.Errorf("encode runner request: %w", marshalErr)
		}
		payload = bytes.NewReader(document)
	}
	token, err := client.tokens.CreateToken(ctx, microvmID, runnerPort)
	if err != nil {
		return nil, fmt.Errorf("create port-scoped MicroVM token: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, method, base.String(), payload)
	if err != nil {
		return nil, fmt.Errorf("create runner request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-aws-proxy-auth", token)
	request.Header.Set("X-aws-proxy-port", fmt.Sprint(runnerPort))
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("call runner endpoint: %w", err)
	}
	defer response.Body.Close()
	document, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read runner response: %w", err)
	}
	if len(document) >= maxResponseBytes {
		return nil, fmt.Errorf("runner response exceeds %d bytes", maxResponseBytes-1)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("runner returned HTTP %d", response.StatusCode)
	}
	return document, nil
}

// endpoint normalizes ACK status and blocks redirects, ports, and SSRF origins.
func (client *Client) endpoint(value string) (*url.URL, error) {
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("parse MicroVM endpoint: %w", err)
	}
	expectedSuffix := ".lambda-microvm." + client.region + ".on.aws"
	if parsed.Scheme != "https" || parsed.User != nil || parsed.Port() != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" ||
		!strings.HasSuffix(strings.ToLower(parsed.Hostname()), expectedSuffix) {
		return nil, fmt.Errorf("reject unexpected MicroVM endpoint origin")
	}
	return parsed, nil
}

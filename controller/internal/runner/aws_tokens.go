package runner

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambdamicrovms"
	"github.com/aws/aws-sdk-go-v2/service/lambdamicrovms/types"
)

// LambdaTokenAPI is the AWS SDK subset required by the orchestrator.
type LambdaTokenAPI interface {
	CreateMicrovmAuthToken(context.Context, *lambdamicrovms.CreateMicrovmAuthTokenInput, ...func(*lambdamicrovms.Options)) (*lambdamicrovms.CreateMicrovmAuthTokenOutput, error)
}

// AWSTokenProvider obtains JWE tokens without persisting them in Kubernetes.
type AWSTokenProvider struct {
	client LambdaTokenAPI
}

// NewAWSTokenProvider creates a least-capability token provider.
func NewAWSTokenProvider(client LambdaTokenAPI) *AWSTokenProvider {
	return &AWSTokenProvider{client: client}
}

// CreateToken returns a five-minute token restricted to one TCP port.
func (provider *AWSTokenProvider) CreateToken(ctx context.Context, microvmID string, port int32) (string, error) {
	output, err := provider.client.CreateMicrovmAuthToken(ctx, &lambdamicrovms.CreateMicrovmAuthTokenInput{
		AllowedPorts:        []types.PortSpecification{&types.PortSpecificationMemberPort{Value: port}},
		ExpirationInMinutes: aws.Int32(5),
		MicrovmIdentifier:   aws.String(microvmID),
	})
	if err != nil {
		return "", err
	}
	token := output.AuthToken["X-aws-proxy-auth"]
	if token == "" {
		return "", fmt.Errorf("AWS token response did not contain X-aws-proxy-auth")
	}
	return token, nil
}

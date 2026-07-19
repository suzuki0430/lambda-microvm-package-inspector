// Package store persists validated reports outside Kubernetes object status.
package store

import (
	"bytes"
	"context"
	"fmt"
	"path"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3API is the AWS SDK subset required to write report objects.
type S3API interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// References contains durable machine-readable and human-readable report URIs.
type References struct {
	JSONURI     string
	MarkdownURI string
}

// S3Store writes immutable-by-key report bundles to a versioned encrypted bucket.
type S3Store struct {
	client S3API
	bucket string
	prefix string
}

// NewS3Store constructs a report store for one infrastructure-owned bucket.
func NewS3Store(client S3API, bucket, prefix string) *S3Store {
	return &S3Store{client: client, bucket: bucket, prefix: prefix}
}

// References deterministically derives report URIs without performing I/O.
func (store *S3Store) References(namespace, name, uid string) References {
	base := path.Join(store.prefix, namespace, name, uid)
	return References{
		JSONURI:     fmt.Sprintf("s3://%s/%s", store.bucket, path.Join(base, "report.json")),
		MarkdownURI: fmt.Sprintf("s3://%s/%s", store.bucket, path.Join(base, "report.md")),
	}
}

// Put writes JSON and Markdown under a Kubernetes UID-scoped key.
//
// Retrying this operation is safe. Bucket versioning preserves prior writes,
// while the Kubernetes UID prevents a same-name resource from reusing keys.
func (store *S3Store) Put(ctx context.Context, namespace, name, uid, digest string, jsonReport, markdownReport []byte) (References, error) {
	base := path.Join(store.prefix, namespace, name, uid)
	jsonKey := path.Join(base, "report.json")
	markdownKey := path.Join(base, "report.md")
	if err := store.put(ctx, jsonKey, "application/json", digest, jsonReport); err != nil {
		return References{}, err
	}
	if err := store.put(ctx, markdownKey, "text/markdown; charset=utf-8", digest, markdownReport); err != nil {
		return References{}, err
	}
	return store.References(namespace, name, uid), nil
}

// put writes one bounded report object with digest metadata for operator checks.
func (store *S3Store) put(ctx context.Context, key, contentType, digest string, document []byte) error {
	_, err := store.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(store.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(document),
		ContentType: aws.String(contentType),
		Metadata: map[string]string{
			"report-sha256": digest,
		},
	})
	if err != nil {
		return fmt.Errorf("put s3://%s/%s: %w", store.bucket, key, err)
	}
	return nil
}

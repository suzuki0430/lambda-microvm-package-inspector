package store

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type putCall struct {
	key         string
	contentType string
	metadata    map[string]string
	body        string
}

type fakeS3 struct {
	calls []putCall
}

// PutObject records report objects without making an AWS request.
func (fake *fakeS3) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	document, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	fake.calls = append(fake.calls, putCall{
		key: *input.Key, contentType: *input.ContentType, metadata: input.Metadata, body: string(document),
	})
	return &s3.PutObjectOutput{}, nil
}

// TestPutStoresTwoUIDScopedObjects verifies idempotent keys and digest metadata.
func TestPutStoresTwoUIDScopedObjects(t *testing.T) {
	t.Parallel()
	fake := &fakeS3{}
	store := NewS3Store(fake, "reports-bucket", "reports")
	digest := strings.Repeat("a", 64)

	references, err := store.Put(context.Background(), "system", "good", "uid-1", digest, []byte(`{}`), []byte("# report\n"))
	if err != nil {
		t.Fatalf("put report: %v", err)
	}
	if len(fake.calls) != 2 || fake.calls[0].key != "reports/system/good/uid-1/report.json" {
		t.Fatalf("unexpected S3 calls: %#v", fake.calls)
	}
	if fake.calls[0].metadata["report-sha256"] != digest || fake.calls[1].contentType != "text/markdown; charset=utf-8" {
		t.Fatalf("missing report metadata: %#v", fake.calls)
	}
	if references.JSONURI != "s3://reports-bucket/reports/system/good/uid-1/report.json" {
		t.Fatalf("unexpected report URI: %s", references.JSONURI)
	}
}

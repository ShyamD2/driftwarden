package terraform

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type mockS3Client struct {
	objects map[string][]byte
}

func (m *mockS3Client) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	contents := make([]s3Types.Object, 0)
	prefix := aws.ToString(params.Prefix)

	for k := range m.objects {
		if prefix == "" || len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			contents = append(contents, s3Types.Object{
				Key: aws.String(k),
			})
		}
	}
	return &s3.ListObjectsV2Output{
		Contents:    contents,
		IsTruncated: aws.Bool(false),
	}, nil
}

func (m *mockS3Client) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	key := aws.ToString(params.Key)
	data, ok := m.objects[key]
	if !ok {
		return nil, fmt.Errorf("NoSuchKey: %s", key)
	}
	return &s3.GetObjectOutput{
		Body: io.NopCloser(bytes.NewReader(data)),
	}, nil
}

func TestParseS3GlobURI(t *testing.T) {
	tests := []struct {
		uri         string
		wantBucket  string
		wantPrefix  string
		wantPattern string
	}{
		{
			uri:         "s3://my-bucket/env/*/*.tfstate",
			wantBucket:  "my-bucket",
			wantPrefix:  "env/",
			wantPattern: "env/*/*.tfstate",
		},
		{
			uri:         "s3://my-bucket/state.tfstate",
			wantBucket:  "my-bucket",
			wantPrefix:  "state.tfstate",
			wantPattern: "state.tfstate",
		},
		{
			uri:         "s3://my-bucket/*.tfstate",
			wantBucket:  "my-bucket",
			wantPrefix:  "",
			wantPattern: "*.tfstate",
		},
	}

	for _, tt := range tests {
		got, err := ParseS3GlobURI(tt.uri)
		if err != nil {
			t.Fatalf("ParseS3GlobURI(%q) error: %v", tt.uri, err)
		}
		if got.Bucket != tt.wantBucket {
			t.Errorf("Bucket = %q; want %q", got.Bucket, tt.wantBucket)
		}
		if got.Prefix != tt.wantPrefix {
			t.Errorf("Prefix = %q; want %q", got.Prefix, tt.wantPrefix)
		}
		if got.Pattern != tt.wantPattern {
			t.Errorf("Pattern = %q; want %q", got.Pattern, tt.wantPattern)
		}
	}
}

func TestMatchS3KeyGlob(t *testing.T) {
	tests := []struct {
		pattern string
		key     string
		want    bool
	}{
		{"env/*/*.tfstate", "env/prod/terraform.tfstate", true},
		{"env/*/*.tfstate", "env/staging/app.tfstate", true},
		{"env/*/*.tfstate", "env/prod/nested/terraform.tfstate", false},
		{"env/**/*.tfstate", "env/prod/nested/terraform.tfstate", true},
		{"*.tfstate", "terraform.tfstate", true},
		{"*.tfstate", "sub/terraform.tfstate", false},
	}

	for _, tt := range tests {
		got := MatchS3KeyGlob(tt.pattern, tt.key)
		if got != tt.want {
			t.Errorf("MatchS3KeyGlob(%q, %q) = %v; want %v", tt.pattern, tt.key, got, tt.want)
		}
	}
}

func TestS3Backend_FetchAndDeduplicate(t *testing.T) {
	state1 := `{
		"version": 4,
		"serial": 10,
		"resources": [
			{
				"mode": "managed",
				"type": "aws_security_group",
				"name": "web",
				"instances": [
					{
						"attributes": {
							"id": "sg-111",
							"arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-111"
						}
					}
				]
			}
		]
	}`

	// Higher serial (50) for the same resource
	state2 := `{
		"version": 4,
		"serial": 50,
		"resources": [
			{
				"mode": "managed",
				"type": "aws_security_group",
				"name": "web",
				"instances": [
					{
						"attributes": {
							"id": "sg-111",
							"arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-111",
							"description": "updated in later serial"
						}
					}
				]
			}
		]
	}`

	mock := &mockS3Client{
		objects: map[string][]byte{
			"env/dev/terraform.tfstate":  []byte(state1),
			"env/prod/terraform.tfstate": []byte(state2),
		},
	}

	parser := NewStateParser("us-east-1", "123456789012")
	backend := NewS3Backend(mock, parser)

	result, err := backend.FetchAndAggregateStates(context.Background(), "s3://terraform-states/env/*/*.tfstate")
	if err != nil {
		t.Fatalf("FetchAndAggregateStates failed: %v", err)
	}

	if len(result.MatchedObjects) != 2 {
		t.Fatalf("expected 2 matched objects, got %d", len(result.MatchedObjects))
	}

	if len(result.Resources) != 1 {
		t.Fatalf("expected 1 deduplicated resource, got %d", len(result.Resources))
	}

	res := result.Resources[0]
	if res.ProviderID != "sg-111" {
		t.Errorf("expected ProviderID sg-111, got %s", res.ProviderID)
	}

	// Verify that state2 (serial 50) was chosen over state1 (serial 10)
	if res.Attributes["description"] != "updated in later serial" {
		t.Errorf("expected resource from serial 50, got attributes: %v", res.Attributes)
	}
}

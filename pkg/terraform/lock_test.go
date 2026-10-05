package terraform

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/ShyamD2/driftwarden/pkg/errors"
	"github.com/ShyamD2/driftwarden/pkg/models"
)

type mockDynamoDBClient struct {
	locked   bool
	lockInfo string
}

func (m *mockDynamoDBClient) GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if !m.locked {
		return &dynamodb.GetItemOutput{Item: nil}, nil
	}
	return &dynamodb.GetItemOutput{
		Item: map[string]dynamodbTypes.AttributeValue{
			"LockID": &dynamodbTypes.AttributeValueMemberS{Value: "my-lock-id"},
			"Info":   &dynamodbTypes.AttributeValueMemberS{Value: m.lockInfo},
		},
	}, nil
}

func TestAcquireStateSnapshot_Locked_FailsWhenNoHistorical(t *testing.T) {
	dynamoMock := &mockDynamoDBClient{
		locked:   true,
		lockInfo: `{"ID":"lock-123","Who":"developer@company","Operation":"apply"}`,
	}

	opts := LockSnapshotOptions{
		DynamoClient:            dynamoMock,
		TableName:               "terraform-lock-table",
		LockID:                  "my-lock-id",
		WaitForLock:             0,
		AllowHistoricalSnapshot: false,
		S3VersionID:             "",
	}

	res, err := AcquireStateSnapshot(context.Background(), opts)
	if res != nil {
		t.Fatalf("expected nil result on locked state, got %v", res)
	}
	if err == nil {
		t.Fatal("expected ErrStateLocked error, got nil")
	}

	classified := errors.Classify(err)
	if classified.Code != errors.ErrStateLocked {
		t.Fatalf("expected error code ErrStateLocked, got %v", classified.Code)
	}

	// Verify that DetermineScanExitCode maps this error to ExitStateLocked (code 3)
	exitCode := models.DetermineScanExitCode(nil, false, false, err)
	if exitCode != models.ExitStateLocked {
		t.Fatalf("expected exit code ExitStateLocked (%d), got %d", models.ExitStateLocked, exitCode)
	}
}

func TestAcquireStateSnapshot_Locked_PermittedHistoricalSnapshot(t *testing.T) {
	dynamoMock := &mockDynamoDBClient{
		locked:   true,
		lockInfo: `{"ID":"lock-123","Who":"ci-runner","Operation":"plan"}`,
	}

	s3Mock := &mockS3Client{
		objects: map[string][]byte{
			"terraform.tfstate": []byte(`{"version":4,"serial":1,"resources":[]}`),
		},
	}

	opts := LockSnapshotOptions{
		DynamoClient:            dynamoMock,
		S3Client:                s3Mock,
		TableName:               "terraform-lock-table",
		LockID:                  "my-lock-id",
		Bucket:                  "state-bucket",
		Key:                     "terraform.tfstate",
		WaitForLock:             0,
		AllowHistoricalSnapshot: true,
		S3VersionID:             "v-historical-99",
	}

	res, err := AcquireStateSnapshot(context.Background(), opts)
	if err != nil {
		t.Fatalf("unexpected error with historical snapshot: %v", err)
	}

	if res.SnapshotMode != "HISTORICAL_SNAPSHOT (STALE)" {
		t.Fatalf("expected SnapshotMode 'HISTORICAL_SNAPSHOT (STALE)', got %q", res.SnapshotMode)
	}
	if !res.IsLocked {
		t.Errorf("expected IsLocked to be true")
	}
	if res.LockInfo == nil || res.LockInfo.Who != "ci-runner" {
		t.Errorf("expected lock info from ci-runner, got %v", res.LockInfo)
	}
}

func TestAcquireStateSnapshot_Unlocked(t *testing.T) {
	dynamoMock := &mockDynamoDBClient{
		locked: false,
	}

	s3Mock := &mockS3Client{
		objects: map[string][]byte{
			"terraform.tfstate": []byte(`{"version":4,"serial":1,"resources":[]}`),
		},
	}

	opts := LockSnapshotOptions{
		DynamoClient:            dynamoMock,
		S3Client:                s3Mock,
		TableName:               "terraform-lock-table",
		LockID:                  "my-lock-id",
		Bucket:                  "state-bucket",
		Key:                     "terraform.tfstate",
		WaitForLock:             10 * time.Millisecond,
		AllowHistoricalSnapshot: false,
	}

	res, err := AcquireStateSnapshot(context.Background(), opts)
	if err != nil {
		t.Fatalf("unexpected error when unlocked: %v", err)
	}

	if res.SnapshotMode != "CURRENT" {
		t.Fatalf("expected SnapshotMode 'CURRENT', got %q", res.SnapshotMode)
	}
	if res.IsLocked {
		t.Errorf("expected IsLocked to be false")
	}
}

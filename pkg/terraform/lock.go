package terraform

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/ShyamD2/driftwarden/pkg/errors"
)

// DynamoDBAPI defines the read-only DynamoDB operations required for state locking.
// CRITICAL SAFETY BOUNDARY: Never write, delete, or mutate lock records.
type DynamoDBAPI interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
}

// LockInfo encapsulates details of an active Terraform state lock.
type LockInfo struct {
	ID        string `json:"ID"`
	Operation string `json:"Operation"`
	Info      string `json:"Info"`
	Who       string `json:"Who"`
	Version   string `json:"Version"`
	Created   string `json:"Created"`
}

// LockSnapshotOptions provides parameters for lock-aware read-only state snapshot retrieval.
type LockSnapshotOptions struct {
	DynamoClient            DynamoDBAPI
	S3Client                S3API
	TableName               string
	LockID                  string
	Bucket                  string
	Key                     string
	WaitForLock             time.Duration
	AllowHistoricalSnapshot bool
	S3VersionID             string
	Logger                  *slog.Logger
}

// StateSnapshotResult encapsulates the acquired state data and audit mode.
type StateSnapshotResult struct {
	Data         []byte
	SnapshotMode string // "CURRENT" or "HISTORICAL_SNAPSHOT (STALE)"
	IsLocked     bool
	LockInfo     *LockInfo
}

// CheckLock inspects DynamoDB for an active lock item.
func CheckLock(ctx context.Context, client DynamoDBAPI, tableName, lockID string) (*LockInfo, bool, error) {
	if client == nil || tableName == "" || lockID == "" {
		return nil, false, nil
	}

	resp, err := client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]dynamodbTypes.AttributeValue{
			"LockID": &dynamodbTypes.AttributeValueMemberS{Value: lockID},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, false, fmt.Errorf("failed to query DynamoDB lock table %s: %w", tableName, err)
	}

	if resp.Item == nil || len(resp.Item) == 0 {
		return nil, false, nil
	}

	infoAttr, ok := resp.Item["Info"]
	if !ok {
		return &LockInfo{ID: lockID}, true, nil
	}

	if sAttr, ok := infoAttr.(*dynamodbTypes.AttributeValueMemberS); ok {
		var lock LockInfo
		if err := json.Unmarshal([]byte(sAttr.Value), &lock); err == nil {
			return &lock, true, nil
		}
		return &LockInfo{ID: lockID, Info: sAttr.Value}, true, nil
	}

	return &LockInfo{ID: lockID}, true, nil
}

// AcquireStateSnapshot implements the explicit lock precedence logic:
// 1. If locked and WaitForLock > 0: Poll with exponential jittered backoff until released or timeout expires.
// 2. If still locked (or WaitForLock == 0):
//   - If AllowHistoricalSnapshot == true AND S3VersionID != "":
//     Download historical version from S3, mark "HISTORICAL_SNAPSHOT (STALE)", log prominent warning.
//   - Else:
//     Return ErrStateLocked (Exit code 3).
func AcquireStateSnapshot(ctx context.Context, opts LockSnapshotOptions) (*StateSnapshotResult, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Step 1: Check initial lock status
	lockInfo, isLocked, err := CheckLock(ctx, opts.DynamoClient, opts.TableName, opts.LockID)
	if err != nil {
		return nil, err
	}

	// Step 2: Handle WaitForLock polling with exponential jittered backoff
	if isLocked && opts.WaitForLock > 0 {
		logger.Info("Terraform state is currently locked. Polling for release...",
			"table", opts.TableName, "lock_id", opts.LockID, "wait_timeout", opts.WaitForLock)

		startTime := time.Now()
		backoff := 200 * time.Millisecond
		maxBackoff := 5 * time.Second

		for time.Since(startTime) < opts.WaitForLock {
			jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
			sleepDuration := backoff + jitter

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(sleepDuration):
			}

			lockInfo, isLocked, err = CheckLock(ctx, opts.DynamoClient, opts.TableName, opts.LockID)
			if err != nil {
				return nil, err
			}
			if !isLocked {
				logger.Info("Lock successfully released during wait period.", "table", opts.TableName, "lock_id", opts.LockID)
				break
			}

			backoff = backoff * 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}

	// Step 3: Branch on persistent lock status
	if isLocked {
		if opts.AllowHistoricalSnapshot && opts.S3VersionID != "" {
			// Permitted historical snapshot branch
			logger.Warn("AUDITING STALE HISTORICAL SNAPSHOT - NOT CURRENT TRUTH",
				"table", opts.TableName,
				"lock_id", opts.LockID,
				"s3_version_id", opts.S3VersionID,
				"locked_by", lockInfo.Who,
			)

			if opts.S3Client == nil || opts.Bucket == "" || opts.Key == "" {
				return nil, errors.New(errors.ErrInvalidConfig, "S3 client, bucket, and key must be provided to download historical snapshot")
			}

			getResp, err := opts.S3Client.GetObject(ctx, &s3.GetObjectInput{
				Bucket:    aws.String(opts.Bucket),
				Key:       aws.String(opts.Key),
				VersionId: aws.String(opts.S3VersionID),
			})
			if err != nil {
				return nil, fmt.Errorf("failed to fetch historical S3 state version %s: %w", opts.S3VersionID, err)
			}
			defer getResp.Body.Close()

			data, err := io.ReadAll(getResp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read historical S3 state version: %w", err)
			}

			return &StateSnapshotResult{
				Data:         data,
				SnapshotMode: "HISTORICAL_SNAPSHOT (STALE)",
				IsLocked:     true,
				LockInfo:     lockInfo,
			}, nil
		}

		// State is locked and historical snapshot is not permitted: return ErrStateLocked
		return nil, errors.New(
			errors.ErrStateLocked,
			fmt.Sprintf("state is locked in DynamoDB table %s by %q (operation: %q, lock ID: %s)",
				opts.TableName, lockInfo.Who, lockInfo.Operation, opts.LockID),
		)
	}

	// Unlocked: download current truth
	var data []byte
	if opts.S3Client != nil && opts.Bucket != "" && opts.Key != "" {
		getResp, err := opts.S3Client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(opts.Bucket),
			Key:    aws.String(opts.Key),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to download current S3 state: %w", err)
		}
		defer getResp.Body.Close()

		data, err = io.ReadAll(getResp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read S3 state body: %w", err)
		}
	}

	return &StateSnapshotResult{
		Data:         data,
		SnapshotMode: "CURRENT",
		IsLocked:     false,
		LockInfo:     nil,
	}, nil
}

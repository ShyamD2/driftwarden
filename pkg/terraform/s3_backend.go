package terraform

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

// S3API defines the minimal interface required for S3 operations, allowing mocking in unit tests.
type S3API interface {
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// S3Backend handles S3 state discovery, globbing, and state aggregation.
type S3Backend struct {
	Client      S3API
	StateParser *StateParser
}

// NewS3Backend creates a new S3Backend instance.
func NewS3Backend(client S3API, stateParser *StateParser) *S3Backend {
	return &S3Backend{
		Client:      client,
		StateParser: stateParser,
	}
}

// ParsedS3Glob represents the parsed components of an S3 glob URI.
type ParsedS3Glob struct {
	Bucket  string
	Prefix  string
	Pattern string
}

// ParseS3GlobURI parses an S3 glob URI (e.g., s3://bucket/env/*/*.tfstate) into bucket, prefix up to first wildcard, and pattern.
func ParseS3GlobURI(uri string) (ParsedS3Glob, error) {
	trimmed := strings.TrimSpace(uri)
	if !strings.HasPrefix(trimmed, "s3://") {
		return ParsedS3Glob{}, fmt.Errorf("invalid S3 URI: must start with 's3://': %q", uri)
	}

	pathPart := strings.TrimPrefix(trimmed, "s3://")
	slashIdx := strings.Index(pathPart, "/")
	if slashIdx == -1 {
		return ParsedS3Glob{
			Bucket:  pathPart,
			Prefix:  "",
			Pattern: "*",
		}, nil
	}

	bucket := pathPart[:slashIdx]
	keyPattern := pathPart[slashIdx+1:]

	// Find first wildcard character (* or ?)
	wildcardIdx := strings.IndexAny(keyPattern, "*?")
	var prefix string
	if wildcardIdx == -1 {
		prefix = keyPattern
	} else {
		// Cut up to the last slash before the first wildcard to establish directory prefix
		lastSlashBeforeWildcard := strings.LastIndex(keyPattern[:wildcardIdx], "/")
		if lastSlashBeforeWildcard == -1 {
			prefix = ""
		} else {
			prefix = keyPattern[:lastSlashBeforeWildcard+1]
		}
	}

	return ParsedS3Glob{
		Bucket:  bucket,
		Prefix:  prefix,
		Pattern: keyPattern,
	}, nil
}

// MatchS3KeyGlob matches an S3 object key against a glob pattern.
func MatchS3KeyGlob(pattern, key string) bool {
	// If exact match
	if pattern == key {
		return true
	}

	patParts := strings.Split(pattern, "/")
	keyParts := strings.Split(key, "/")

	// If pattern contains "**", handle multi-segment match
	hasDoubleStar := false
	for _, p := range patParts {
		if p == "**" {
			hasDoubleStar = true
			break
		}
	}

	if !hasDoubleStar {
		if len(patParts) != len(keyParts) {
			return false
		}
		for i := range patParts {
			matched, err := path.Match(patParts[i], keyParts[i])
			if err != nil || !matched {
				return false
			}
		}
		return true
	}

	// Double-star glob matching
	return matchGlobRecursive(patParts, keyParts)
}

func matchGlobRecursive(pat, key []string) bool {
	if len(pat) == 0 {
		return len(key) == 0
	}
	if pat[0] == "**" {
		// Try matching remainder of pattern with 0..len(key) parts
		for i := 0; i <= len(key); i++ {
			if matchGlobRecursive(pat[1:], key[i:]) {
				return true
			}
		}
		return false
	}
	if len(key) == 0 {
		return false
	}
	matched, err := path.Match(pat[0], key[0])
	if err != nil || !matched {
		return false
	}
	return matchGlobRecursive(pat[1:], key[1:])
}

// AggregatedStateResult encapsulates deduplicated resources and loaded state metadata.
type AggregatedStateResult struct {
	Resources      []models.CanonicalResource
	StateFiles     map[string]*StateFile
	MatchedObjects []string
}

// FetchAndAggregateStates lists objects matching the S3 glob, downloads them, and deduplicates resources by highest serial.
func (b *S3Backend) FetchAndAggregateStates(ctx context.Context, globURI string) (*AggregatedStateResult, error) {
	parsed, err := ParseS3GlobURI(globURI)
	if err != nil {
		return nil, err
	}

	// 1. List objects using paginator
	paginator := s3.NewListObjectsV2Paginator(b.Client, &s3.ListObjectsV2Input{
		Bucket: aws.String(parsed.Bucket),
		Prefix: aws.String(parsed.Prefix),
	})

	matchedKeys := make([]string, 0)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("error listing S3 objects in bucket %s: %w", parsed.Bucket, err)
		}

		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			if MatchS3KeyGlob(parsed.Pattern, key) {
				matchedKeys = append(matchedKeys, key)
			}
		}
	}

	stateFiles := make(map[string]*StateFile)
	resourceMap := make(map[string]struct {
		res    models.CanonicalResource
		serial int64
		origin string
	})

	// 2. Download and parse each matched state file
	for _, key := range matchedKeys {
		origin := fmt.Sprintf("s3://%s/%s", parsed.Bucket, key)
		getResp, err := b.Client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(parsed.Bucket),
			Key:    aws.String(key),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to download state file %s: %w", origin, err)
		}

		bodyBytes, err := io.ReadAll(getResp.Body)
		getResp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read body of state file %s: %w", origin, err)
		}

		resList, stateFile, err := b.StateParser.ParseBytes(bodyBytes, origin)
		if err != nil {
			return nil, fmt.Errorf("failed to parse state file %s: %w", origin, err)
		}

		stateFiles[origin] = stateFile

		// 3. Multi-state deduplication by CanonicalID: resolve via latest serial
		for _, res := range resList {
			id := res.CanonicalID
			if id == "" {
				id = fmt.Sprintf("%s/%s", res.Type, res.Name)
			}

			existing, exists := resourceMap[id]
			if !exists || stateFile.Serial > existing.serial {
				res.IdentityEvidence = append(res.IdentityEvidence,
					fmt.Sprintf("multi-state resolved from origin %s with serial %d", origin, stateFile.Serial))
				resourceMap[id] = struct {
					res    models.CanonicalResource
					serial int64
					origin string
				}{
					res:    res,
					serial: stateFile.Serial,
					origin: origin,
				}
			}
		}
	}

	resultResources := make([]models.CanonicalResource, 0, len(resourceMap))
	for _, item := range resourceMap {
		resultResources = append(resultResources, item.res)
	}

	return &AggregatedStateResult{
		Resources:      resultResources,
		StateFiles:     stateFiles,
		MatchedObjects: matchedKeys,
	}, nil
}

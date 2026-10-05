package collector

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	dwErrors "github.com/ShyamD2/driftwarden/pkg/errors"
	"github.com/ShyamD2/driftwarden/pkg/identity"
	"github.com/ShyamD2/driftwarden/pkg/models"
)

// S3BucketClientAPI defines the operations needed for S3 Bucket collection.
type S3BucketClientAPI interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketEncryption(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetBucketTagging(ctx context.Context, params *s3.GetBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error)
}

var defaultS3ClientFactory = func(cfg aws.Config, region string) S3BucketClientAPI {
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		if region != "" {
			o.Region = region
		}
	})
}

// S3BucketCollector collects S3 bucket configurations.
type S3BucketCollector struct {
	clientFactory func(cfg aws.Config, region string) S3BucketClientAPI
}

func NewS3BucketCollector() *S3BucketCollector {
	return &S3BucketCollector{clientFactory: defaultS3ClientFactory}
}

func (c *S3BucketCollector) ResourceType() string {
	return identity.TypeAWSS3Bucket
}

func (c *S3BucketCollector) Capabilities() models.CollectorCapabilities {
	return models.CollectorCapabilities{
		Discover:        true,
		Normalize:       true,
		Compare:         true,
		SecurityAnalyze: true,
		CostEstimate:    false,
		Reconcile:       true,
	}
}

// Collect lists S3 buckets. Note: s3.ListBuckets is inherently non-paginated in AWS SDK v2.
func (c *S3BucketCollector) Collect(ctx context.Context, cfg aws.Config, region string) ([]models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)
	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, dwErrors.Classify(err)
	}

	var results []models.CanonicalResource
	for _, b := range out.Buckets {
		bucketName := aws.ToString(b.Name)
		canRes := c.buildBucketResource(ctx, client, bucketName, region)
		results = append(results, canRes)
	}
	return results, nil
}

func (c *S3BucketCollector) Get(ctx context.Context, cfg aws.Config, region string, providerID string) (*models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)

	// Verify bucket exists via ListBuckets
	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, dwErrors.Classify(err)
	}

	found := false
	for _, b := range out.Buckets {
		if aws.ToString(b.Name) == providerID {
			found = true
			break
		}
	}

	if !found {
		return nil, dwErrors.New(dwErrors.ErrNotFound, fmt.Sprintf("s3 bucket %s not found", providerID))
	}

	res := c.buildBucketResource(ctx, client, providerID, region)
	return &res, nil
}

func (c *S3BucketCollector) buildBucketResource(ctx context.Context, client S3BucketClientAPI, bucketName, region string) models.CanonicalResource {
	attrs := map[string]any{
		"bucket": bucketName,
		"id":     bucketName,
	}

	// 1. Query Public Access Block
	pabResp, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
	})
	if err == nil && pabResp.PublicAccessBlockConfiguration != nil {
		attrs["block_public_acls"] = pabResp.PublicAccessBlockConfiguration.BlockPublicAcls
		attrs["block_public_policy"] = pabResp.PublicAccessBlockConfiguration.BlockPublicPolicy
		attrs["ignore_public_acls"] = pabResp.PublicAccessBlockConfiguration.IgnorePublicAcls
		attrs["restrict_public_buckets"] = pabResp.PublicAccessBlockConfiguration.RestrictPublicBuckets
	}

	// 2. Query Encryption
	encResp, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: aws.String(bucketName),
	})
	if err == nil && encResp.ServerSideEncryptionConfiguration != nil {
		attrs["server_side_encryption_enabled"] = true
	} else {
		attrs["server_side_encryption_enabled"] = false
	}

	// 3. Query Tags
	tags := make(map[string]string)
	tagResp, err := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
		Bucket: aws.String(bucketName),
	})
	if err == nil {
		for _, t := range tagResp.TagSet {
			tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
	}

	canonicalID := identity.CanonicalIDForType(identity.TypeAWSS3Bucket, "", "", bucketName)

	return models.CanonicalResource{
		CanonicalID:        canonicalID,
		Type:               identity.TypeAWSS3Bucket,
		ProviderID:         bucketName,
		Name:               bucketName,
		AccountID:          "",
		Region:             region,
		Attributes:         attrs,
		Tags:               tags,
		Source:             models.SourceLive,
		Availability:       models.AvailabilityPresent,
		IdentityConfidence: 1.0,
		IdentityEvidence: []string{
			"observed via s3.ListBuckets and security sub-resource queries",
		},
	}
}

func init() {
	Register(NewS3BucketCollector())
}

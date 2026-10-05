package identity

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// CanonicalComponents holds the segments of a CanonicalURN.
type CanonicalComponents struct {
	Partition    string
	Service      string
	Region       string
	AccountID    string
	ResourceType string
	ResourceID   string
}

// GenerateCanonicalID produces a standardized deterministic URN:
// aws:<partition>:<service>:<region>:<account>:<resource_type>/<resource_id>
//
// Invariants:
// 1. Equivalent AWS resources MUST produce byte-for-byte identical CanonicalIDs.
// 2. Global AWS resources (e.g. S3) permit empty region and account: aws:aws:s3:::bucket/<bucket_name>.
// 3. IAM resources permit empty region: aws:aws:iam::<account>:role/<name>.
func GenerateCanonicalID(c CanonicalComponents) string {
	partition := strings.TrimSpace(aws.ToString(&c.Partition))
	if partition == "" {
		partition = "aws"
	} else {
		partition = strings.ToLower(partition)
	}

	service := strings.ToLower(strings.TrimSpace(aws.ToString(&c.Service)))
	region := strings.TrimSpace(aws.ToString(&c.Region))
	account := strings.TrimSpace(aws.ToString(&c.AccountID))
	resType := strings.TrimSpace(aws.ToString(&c.ResourceType))
	resID := strings.TrimSpace(aws.ToString(&c.ResourceID))

	return fmt.Sprintf("aws:%s:%s:%s:%s:%s/%s", partition, service, region, account, resType, resID)
}

// ParseCanonicalID parses a canonical URN into its components.
func ParseCanonicalID(urn string) (CanonicalComponents, error) {
	trimmed := strings.TrimSpace(urn)
	if !strings.HasPrefix(trimmed, "aws:") {
		return CanonicalComponents{}, fmt.Errorf("invalid canonical URN: missing 'aws:' prefix: %q", urn)
	}

	// Format: aws:<partition>:<service>:<region>:<account>:<resource_type>/<resource_id>
	// Split by colons: prefix "aws", partition, service, region, account, remainder
	parts := strings.Split(trimmed, ":")
	if len(parts) < 6 {
		return CanonicalComponents{}, fmt.Errorf("invalid canonical URN structure: insufficient colon-separated segments: %q", urn)
	}

	partition := parts[1]
	service := parts[2]
	region := parts[3]
	account := parts[4]
	remainder := strings.Join(parts[5:], ":")

	slashIdx := strings.Index(remainder, "/")
	if slashIdx == -1 {
		return CanonicalComponents{}, fmt.Errorf("invalid canonical URN structure: missing '/' separator between resource type and id in %q", remainder)
	}

	resType := remainder[:slashIdx]
	resID := remainder[slashIdx+1:]

	if resType == "" || resID == "" {
		return CanonicalComponents{}, errors.New("canonical URN must specify non-empty resource type and id")
	}

	return CanonicalComponents{
		Partition:    partition,
		Service:      service,
		Region:       region,
		AccountID:    account,
		ResourceType: resType,
		ResourceID:   resID,
	}, nil
}

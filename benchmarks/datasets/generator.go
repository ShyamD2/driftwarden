package datasets

import (
	"encoding/json"
	"fmt"
	"math/rand"

	"github.com/ShyamD2/driftwarden/pkg/models"
	"github.com/ShyamD2/driftwarden/pkg/terraform"
)

var resourceTypes = []string{
	"aws_instance",
	"aws_security_group",
	"aws_s3_bucket",
	"aws_vpc",
	"aws_subnet",
}

// GenerateSyntheticState creates a valid Terraform State Schema v4 payload with N resources.
func GenerateSyntheticState(count int) []byte {
	r := rand.New(rand.NewSource(42)) // Deterministic seed

	state := terraform.StateFile{
		Version:          4,
		TerraformVersion: "1.5.0",
		Serial:           10,
		Lineage:          "synthetic-lineage-benchmark",
		Resources:        make([]terraform.StateResource, count),
	}

	for i := 0; i < count; i++ {
		resType := resourceTypes[i%len(resourceTypes)]
		var attrs map[string]any

		switch resType {
		case "aws_instance":
			attrs = map[string]any{
				"id":            fmt.Sprintf("i-%012d", i),
				"arn":           fmt.Sprintf("arn:aws:ec2:us-east-1:123456789012:instance/i-%012d", i),
				"instance_type": "t3.micro",
				"ami":           "ami-0c55b159cbfafe1f0",
				"tags": map[string]any{
					"Environment": "production",
					"Name":        fmt.Sprintf("server-%d", i),
					"Owner":       "platform-engineering",
					"CostCenter":  "cc-104",
				},
			}
		case "aws_security_group":
			attrs = map[string]any{
				"id":          fmt.Sprintf("sg-%012d", i),
				"arn":         fmt.Sprintf("arn:aws:ec2:us-east-1:123456789012:security_group/sg-%012d", i),
				"name":        fmt.Sprintf("sg-%d", i),
				"description": "Benchmark security group",
				"ingress": []any{
					map[string]any{
						"protocol":    "tcp",
						"from_port":   443,
						"to_port":     443,
						"cidr_blocks": []any{"10.0.0.0/8"},
					},
				},
			}
		case "aws_s3_bucket":
			attrs = map[string]any{
				"id":            fmt.Sprintf("benchmark-bucket-%08d", i),
				"bucket":        fmt.Sprintf("benchmark-bucket-%08d", i),
				"arn":           fmt.Sprintf("arn:aws:s3:::benchmark-bucket-%08d", i),
				"force_destroy": false,
			}
		case "aws_vpc":
			attrs = map[string]any{
				"id":                   fmt.Sprintf("vpc-%012d", i),
				"cidr_block":           "10.0.0.0/16",
				"enable_dns_hostnames": true,
			}
		case "aws_subnet":
			attrs = map[string]any{
				"id":         fmt.Sprintf("subnet-%012d", i),
				"vpc_id":     fmt.Sprintf("vpc-%012d", r.Intn(100)),
				"cidr_block": fmt.Sprintf("10.0.%d.0/24", i%250),
			}
		}

		state.Resources[i] = terraform.StateResource{
			Mode:     "managed",
			Type:     resType,
			Name:     fmt.Sprintf("res_%d", i),
			Provider: `provider["registry.terraform.io/hashicorp/aws"]`,
			Instances: []terraform.StateInstance{
				{
					SchemaVersion: 1,
					Attributes:    attrs,
				},
			},
		}
	}

	data, _ := json.Marshal(state)
	return data
}

// GenerateSyntheticCanonicalTriples generates matching slices for 3-source correlation testing.
func GenerateSyntheticCanonicalTriples(count int, driftRatio float64) ([]models.CanonicalResource, []models.CanonicalResource, []models.CanonicalResource) {
	r := rand.New(rand.NewSource(42))

	desired := make([]models.CanonicalResource, count)
	state := make([]models.CanonicalResource, count)
	live := make([]models.CanonicalResource, count)

	for i := 0; i < count; i++ {
		resType := resourceTypes[i%len(resourceTypes)]
		providerID := fmt.Sprintf("res-%010d", i)
		canonicalID := fmt.Sprintf("aws:aws:ec2:us-east-1:123456789012:%s/%s", resType, providerID)

		baseAttrs := map[string]any{
			"instance_type": "t3.micro",
			"tier":          "production",
		}

		desired[i] = models.CanonicalResource{
			CanonicalID:  canonicalID,
			Type:         resType,
			ProviderID:   providerID,
			Source:       models.SourceDesired,
			Availability: models.AvailabilityPresent,
			Attributes:   copyMap(baseAttrs),
		}

		state[i] = models.CanonicalResource{
			CanonicalID:  canonicalID,
			Type:         resType,
			ProviderID:   providerID,
			Source:       models.SourceState,
			Availability: models.AvailabilityPresent,
			Attributes:   copyMap(baseAttrs),
		}

		liveAttrs := copyMap(baseAttrs)
		// Inject intentional drift based on ratio
		if r.Float64() < driftRatio {
			liveAttrs["instance_type"] = "t3.medium"
		}

		live[i] = models.CanonicalResource{
			CanonicalID:  canonicalID,
			Type:         resType,
			ProviderID:   providerID,
			Source:       models.SourceLive,
			Availability: models.AvailabilityPresent,
			Attributes:   liveAttrs,
		}
	}

	return desired, state, live
}

func copyMap(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

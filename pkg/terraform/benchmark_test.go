package terraform

import (
	"encoding/json"
	"fmt"
	"runtime"
	"testing"
	"time"
)

func generateSyntheticStateV4(count int) []byte {
	state := StateFile{
		Version:          4,
		TerraformVersion: "1.5.0",
		Serial:           10,
		Lineage:          "synthetic-lineage-12345",
		Resources:        make([]StateResource, count),
	}

	for i := 0; i < count; i++ {
		state.Resources[i] = StateResource{
			Mode:     "managed",
			Type:     "aws_instance",
			Name:     fmt.Sprintf("server_%d", i),
			Provider: `provider["registry.terraform.io/hashicorp/aws"]`,
			Instances: []StateInstance{
				{
					SchemaVersion: 1,
					Attributes: map[string]any{
						"id":            fmt.Sprintf("i-%012d", i),
						"arn":           fmt.Sprintf("arn:aws:ec2:us-east-1:123456789012:instance/i-%012d", i),
						"instance_type": "t3.micro",
						"ami":           "ami-0c55b159cbfafe1f0",
						"tags": map[string]any{
							"Environment": "production",
							"Name":        fmt.Sprintf("web-server-%d", i),
						},
					},
				},
			},
		}
	}

	data, _ := json.Marshal(state)
	return data
}

func printBenchmarkHardwareContext() {
	fmt.Printf("\n--- Benchmark Hardware & Execution Environment ---\n")
	fmt.Printf("OS/Arch:      %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("CPUs (cores): %d\n", runtime.NumCPU())
	fmt.Printf("Go Version:   %s\n", runtime.Version())
	fmt.Printf("Timestamp:    %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Printf("---------------------------------------------------\n\n")
}

func BenchmarkStateParsing(b *testing.B) {
	printBenchmarkHardwareContext()
	data := generateSyntheticStateV4(1000)
	parser := NewStateParser("us-east-1", "123456789012")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resources, _, err := parser.ParseBytes(data, "in-memory.tfstate")
		if err != nil {
			b.Fatalf("parsing error: %v", err)
		}
		if len(resources) != 1000 {
			b.Fatalf("expected 1000 resources, got %d", len(resources))
		}
	}
}

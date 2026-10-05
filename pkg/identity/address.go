package identity

import (
	"fmt"
	"regexp"
	"strings"
)

// TerraformAddress represents the parsed components of a Terraform resource address.
type TerraformAddress struct {
	FullAddress string
	Module      string
	Type        string
	Name        string
	Key         string
}

// Regex to capture:
// Optional module prefix: (module\.[a-zA-Z0-9_.-]+(\[[^\]]+\])?\.)*
// Resource type: ([a-zA-Z0-9_]+)
// Resource name: ([a-zA-Z0-9_-]+)
// Optional index/key: (\[["']?([^"'\]]+)["']?\])?
var tfAddressRegex = regexp.MustCompile(`^(?:(module\..+?)\.)?([a-zA-Z0-9_]+)\.([a-zA-Z0-9_-]+)(?:\[(?:["']?([^"'\]]+)["']?)\])?$`)

// ParseTerraformAddress parses a Terraform resource address expression into its constituent parts.
// Example:
//
//	aws_security_group.web["prod"] -> Type: aws_security_group, Name: web, Key: prod
//	aws_instance.server            -> Type: aws_instance, Name: server, Key: ""
//	aws_subnet.public[0]           -> Type: aws_subnet, Name: public, Key: 0
//	module.vpc.aws_vpc.main        -> Module: module.vpc, Type: aws_vpc, Name: main, Key: ""
func ParseTerraformAddress(addr string) (TerraformAddress, error) {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return TerraformAddress{}, fmt.Errorf("empty terraform address")
	}

	matches := tfAddressRegex.FindStringSubmatch(trimmed)
	if len(matches) < 4 {
		return TerraformAddress{}, fmt.Errorf("invalid terraform resource address: %q", addr)
	}

	module := matches[1]
	resType := matches[2]
	resName := matches[3]
	key := ""
	if len(matches) >= 5 {
		key = matches[4]
	}

	return TerraformAddress{
		FullAddress: trimmed,
		Module:      module,
		Type:        resType,
		Name:        resName,
		Key:         key,
	}, nil
}

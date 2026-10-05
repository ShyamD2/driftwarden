package analyzer

import (
	_ "embed"
	"encoding/json"
	"time"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

//go:embed pricing/us-east-1.json
var defaultPricingJSON []byte

// CostProvider defines methods for estimating cloud expenditure and drift-induced financial waste.
type CostProvider interface {
	EstimateMonthlyWaste(res models.CanonicalResource) (*models.CostEstimate, error)
	Estimate(res models.CanonicalResource) *models.CostEstimate
	EstimateDriftWaste(item *models.DriftItem) *models.CostEstimate
}

// DisabledCostProvider returns nil estimates when cost analysis is disabled via --no-cost.
type DisabledCostProvider struct{}

func (d *DisabledCostProvider) EstimateMonthlyWaste(res models.CanonicalResource) (*models.CostEstimate, error) {
	return nil, nil
}

func (d *DisabledCostProvider) Estimate(res models.CanonicalResource) *models.CostEstimate {
	return nil
}

func (d *DisabledCostProvider) EstimateDriftWaste(item *models.DriftItem) *models.CostEstimate {
	return nil
}

type staticPricingData struct {
	EC2Hourly    map[string]float64 `json:"ec2_instances_hourly"`
	EBSMonthlyGB map[string]float64 `json:"ebs_storage_monthly_per_gb"`
	EIPHourly    float64            `json:"elastic_ip_idle_hourly"`
}

// StaticCostProvider estimates costs using static AWS pricing tables.
type StaticCostProvider struct {
	pricing staticPricingData
	region  string
}

// StaticPricingProvider is an alias for StaticCostProvider as specified by Phase 5 contract.
type StaticPricingProvider = StaticCostProvider

// NewStaticCostProvider initializes a provider with embedded or customized pricing.
func NewStaticCostProvider(region string, customJSON []byte) (*StaticCostProvider, error) {
	data := defaultPricingJSON
	if len(customJSON) > 0 {
		data = customJSON
	}

	var pricing staticPricingData
	if err := json.Unmarshal(data, &pricing); err != nil {
		return nil, err
	}

	if region == "" {
		region = "us-east-1"
	}

	return &StaticCostProvider{
		pricing: pricing,
		region:  region,
	}, nil
}

// NewStaticPricingProvider initializes a StaticPricingProvider.
func NewStaticPricingProvider(region string, customJSON []byte) (*StaticPricingProvider, error) {
	return NewStaticCostProvider(region, customJSON)
}

const hoursPerMonth = 730.0

// EstimateMonthlyWaste calculates monthly financial bleed strictly for supported resources:
// aws_instance, unattached aws_ebs_volume, and unassociated aws_eip.
// Returns nil for unsupported types (SG, VPC, IAM).
func (p *StaticCostProvider) EstimateMonthlyWaste(res models.CanonicalResource) (*models.CostEstimate, error) {
	attrs := res.Attributes
	if attrs == nil {
		return nil, nil
	}

	switch res.Type {
	case "aws_instance":
		instanceType, ok := attrs["instance_type"].(string)
		if !ok || instanceType == "" {
			return nil, nil
		}
		hourly, ok := p.pricing.EC2Hourly[instanceType]
		if !ok {
			hourly = 0.0416 // t3.medium fallback
		}
		monthly := hourly * hoursPerMonth
		return &models.CostEstimate{
			AmountMonthly: monthly,
			Currency:      "USD",
			Region:        res.Region,
			PricingSource: "AWS Pricing Static Catalog (us-east-1.json)",
			PricingModel:  "On-Demand Hourly Estimate (730 hrs/mo - Not Exact Billing)",
			RetrievedAt:   time.Now().UTC(),
			Confidence:    0.95,
		}, nil

	case "aws_ebs_volume":
		// Only unattached EBS volumes represent pure waste bleed
		isUnattached := false
		if unattached, ok := attrs["unattached"].(bool); ok && unattached {
			isUnattached = true
		} else if state, ok := attrs["state"].(string); ok && state == "available" {
			isUnattached = true
		}
		if !isUnattached {
			return nil, nil
		}

		sizeGB := getFloatVal(attrs["size"])
		if sizeGB <= 0 {
			sizeGB = 20
		}
		volType, _ := attrs["volume_type"].(string)
		if volType == "" {
			volType = "gp3"
		}
		ratePerGB, ok := p.pricing.EBSMonthlyGB[volType]
		if !ok {
			ratePerGB = 0.08
		}
		monthly := sizeGB * ratePerGB
		return &models.CostEstimate{
			AmountMonthly: monthly,
			Currency:      "USD",
			Region:        res.Region,
			PricingSource: "AWS Pricing Static Catalog (us-east-1.json)",
			PricingModel:  "Unattached Idle EBS Volume Storage Bleed",
			RetrievedAt:   time.Now().UTC(),
			Confidence:    0.95,
		}, nil

	case "aws_eip":
		// Only unassociated Elastic IPs represent idle charges
		isUnassociated := false
		if unassoc, ok := attrs["unassociated"].(bool); ok && unassoc {
			isUnassociated = true
		} else {
			instID, _ := attrs["instance_id"].(string)
			assocID, _ := attrs["association_id"].(string)
			if instID == "" && assocID == "" {
				isUnassociated = true
			}
		}
		if !isUnassociated {
			return nil, nil
		}

		monthly := p.pricing.EIPHourly * hoursPerMonth
		return &models.CostEstimate{
			AmountMonthly: monthly,
			Currency:      "USD",
			Region:        res.Region,
			PricingSource: "AWS Pricing Static Catalog (us-east-1.json)",
			PricingModel:  "Idle Unassociated Elastic IP ($0.005/hr)",
			RetrievedAt:   time.Now().UTC(),
			Confidence:    1.0,
		}, nil

	default:
		// Unsupported types (SG, VPC, IAM) return nil as required
		return nil, nil
	}
}

// Estimate calculates standard resource running cost (for backward compatibility).
func (p *StaticCostProvider) Estimate(res models.CanonicalResource) *models.CostEstimate {
	est, _ := p.EstimateMonthlyWaste(res)
	if est != nil {
		return est
	}
	// Fallback for attached EBS/EIP if general estimation requested
	if res.Type == "aws_ebs_volume" {
		sizeGB := getFloatVal(res.Attributes["size"])
		if sizeGB <= 0 {
			sizeGB = 20
		}
		volType, _ := res.Attributes["volume_type"].(string)
		if volType == "" {
			volType = "gp3"
		}
		ratePerGB := p.pricing.EBSMonthlyGB[volType]
		if ratePerGB == 0 {
			ratePerGB = 0.08
		}
		return &models.CostEstimate{
			AmountMonthly: sizeGB * ratePerGB,
			Currency:      "USD",
			Region:        res.Region,
			PricingSource: "AWS Pricing Static Catalog",
			PricingModel:  "Standard EBS Storage",
			RetrievedAt:   time.Now().UTC(),
			Confidence:    0.95,
		}
	}
	return nil
}

// EstimateDriftWaste determines financial waste caused specifically by drift.
func (p *StaticCostProvider) EstimateDriftWaste(item *models.DriftItem) *models.CostEstimate {
	if item == nil {
		return nil
	}

	// 1. Ghost Resources: absent in cloud -> $0.00 ongoing waste
	if item.Type == models.DriftGhost {
		return &models.CostEstimate{
			AmountMonthly: 0.0,
			Currency:      "USD",
			Region:        item.Resource.Region,
			PricingSource: "AWS Pricing Static Catalog",
			PricingModel:  "Ghost Resource (Absent in Cloud - No Ongoing Waste)",
			RetrievedAt:   time.Now().UTC(),
			Confidence:    1.0,
		}
	}

	// 2. Shadow Resources: unmanaged cloud assets -> 100% waste
	if item.Type == models.DriftShadow {
		est, _ := p.EstimateMonthlyWaste(item.Resource)
		if est != nil {
			est.PricingModel = "Unmanaged Shadow Asset (100% Waste Bleed)"
			return est
		}
	}

	// 3. Attribute Drift on instance size: delta cost
	if item.Type == models.DriftAttribute && item.Resource.Type == "aws_instance" {
		if diff, ok := item.Diffs["instance_type"]; ok {
			desiredType, _ := diff.DesiredValue.(string)
			liveType, _ := diff.LiveValue.(string)
			if desiredType != "" && liveType != "" {
				desiredHourly := p.pricing.EC2Hourly[desiredType]
				liveHourly := p.pricing.EC2Hourly[liveType]
				if liveHourly > desiredHourly {
					deltaMonthly := (liveHourly - desiredHourly) * hoursPerMonth
					return &models.CostEstimate{
						AmountMonthly: deltaMonthly,
						Currency:      "USD",
						Region:        item.Resource.Region,
						PricingSource: "AWS Pricing Static Catalog",
						PricingModel:  "Instance Type Oversizing Delta",
						RetrievedAt:   time.Now().UTC(),
						Confidence:    0.95,
					}
				}
			}
		}
	}

	// Default estimation for the resource
	est, _ := p.EstimateMonthlyWaste(item.Resource)
	return est
}

func getFloatVal(v any) float64 {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case float64:
		return val
	case int:
		return float64(val)
	case int64:
		return float64(val)
	default:
		return 0
	}
}

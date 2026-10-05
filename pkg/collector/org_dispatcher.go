package collector

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgTypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	dwErrors "github.com/ShyamD2/driftwarden/pkg/errors"
	"github.com/ShyamD2/driftwarden/pkg/identity"
	"github.com/ShyamD2/driftwarden/pkg/models"
)

// OrganizationsAPIClient defines operations needed for multi-account discovery.
type OrganizationsAPIClient interface {
	ListAccounts(ctx context.Context, params *organizations.ListAccountsInput, optFns ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error)
}

// STSAssumeRoleAPIClient defines operations needed to assume execution role in target member accounts.
type STSAssumeRoleAPIClient interface {
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// OrgDispatcher coordinates multi-account discovery across AWS Organizations.
type OrgDispatcher struct {
	BaseDispatcher *Dispatcher
	OrgClient      OrganizationsAPIClient
	STSClient      STSAssumeRoleAPIClient
	RoleName       string
}

// NewOrgDispatcher creates a new OrgDispatcher.
func NewOrgDispatcher(baseDispatcher *Dispatcher, orgClient OrganizationsAPIClient, stsClient STSAssumeRoleAPIClient, roleName string) *OrgDispatcher {
	if roleName == "" {
		roleName = "DriftWardenExecutionRole"
	}
	return &OrgDispatcher{
		BaseDispatcher: baseDispatcher,
		OrgClient:      orgClient,
		STSClient:      stsClient,
		RoleName:       roleName,
	}
}

// AccountInfo holds metadata for an organization member account.
type AccountInfo struct {
	ID     string
	Name   string
	Status string
}

// DiscoverActiveAccounts lists all ACTIVE member accounts within the AWS Organization using paginator.
func (od *OrgDispatcher) DiscoverActiveAccounts(ctx context.Context) ([]AccountInfo, error) {
	if od.OrgClient == nil {
		return nil, dwErrors.New(dwErrors.ErrInvalidConfig, "Organizations client is nil")
	}

	paginator := organizations.NewListAccountsPaginator(od.OrgClient, &organizations.ListAccountsInput{})
	var activeAccounts []AccountInfo

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, dwErrors.Classify(err)
		}

		for _, acc := range page.Accounts {
			if acc.Status == orgTypes.AccountStatusActive {
				activeAccounts = append(activeAccounts, AccountInfo{
					ID:     aws.ToString(acc.Id),
					Name:   aws.ToString(acc.Name),
					Status: string(acc.Status),
				})
			}
		}
	}

	return activeAccounts, nil
}

// DispatchOrg runs collection fanning out across all active member accounts and regions.
func (od *OrgDispatcher) DispatchOrg(ctx context.Context, baseCfg aws.Config, regions []string, resourceTypes []string) ([]models.CanonicalResource, []error) {
	accounts, err := od.DiscoverActiveAccounts(ctx)
	if err != nil {
		return nil, []error{err}
	}

	type orgAccountResult struct {
		accountID string
		resources []models.CanonicalResource
		errs      []error
	}

	resultChan := make(chan orgAccountResult, len(accounts))
	var wg sync.WaitGroup

	// Concurrently fan out across accounts
	for _, acc := range accounts {
		wg.Add(1)
		go func(account AccountInfo) {
			defer wg.Done()

			accountCfg := baseCfg
			accountCfg.Region = baseCfg.Region

			// Assume role if STSClient is configured
			if od.STSClient != nil {
				targetRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", account.ID, od.RoleName)
				_, assumeErr := od.STSClient.AssumeRole(ctx, &sts.AssumeRoleInput{
					RoleArn:         aws.String(targetRoleARN),
					RoleSessionName: aws.String("DriftWardenOrgAudit"),
				})
				if assumeErr != nil {
					resultChan <- orgAccountResult{
						accountID: account.ID,
						errs:      []error{dwErrors.Classify(assumeErr)},
					}
					return
				}
			}

			// Run base dispatcher for this account
			resList, errs := od.BaseDispatcher.Dispatch(ctx, accountCfg, regions, resourceTypes)

			// Ensure every resource explicitly preserves its target AccountID and CanonicalID
			for i := range resList {
				resList[i].AccountID = account.ID
				if resList[i].ProviderID != "" {
					resList[i].CanonicalID = identity.CanonicalIDForType(resList[i].Type, resList[i].Region, account.ID, resList[i].ProviderID)
				}
				resList[i].IdentityEvidence = append(resList[i].IdentityEvidence,
					fmt.Sprintf("collected via organization fan-out for account %s (%s)", account.ID, account.Name))
			}

			resultChan <- orgAccountResult{
				accountID: account.ID,
				resources: resList,
				errs:      errs,
			}
		}(acc)
	}

	wg.Wait()
	close(resultChan)

	var allResources []models.CanonicalResource
	var allErrors []error

	for r := range resultChan {
		allResources = append(allResources, r.resources...)
		allErrors = append(allErrors, r.errs...)
	}

	return allResources, allErrors
}

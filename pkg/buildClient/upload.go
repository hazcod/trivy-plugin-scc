package buildClient

import (
	"context"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/hazcod/trivy-plugin-scc/pkg/metadata"
	"github.com/pkg/errors"
	"google.golang.org/genproto/googleapis/cloud/securitycenter/v1"
	"strings"
)

func getSCCSeverity(sev string) securitycenter.Finding_Severity {
	switch strings.ToLower(sev) {
	case "low":
		return securitycenter.Finding_LOW
	case "medium":
		return securitycenter.Finding_MEDIUM
	case "high":
		return securitycenter.Finding_HIGH
	case "critical":
		return securitycenter.Finding_CRITICAL
	default:
		return securitycenter.Finding_SEVERITY_UNSPECIFIED
	}
}

func (bc *SCCClient) Upload(results report.Results, tags map[string]string) error {
	ctx := context.Background()

	//gitUser := metadata.GetGitUser(bc.scanPath)

	repoName, branch, err := metadata.GetRepositoryDetails(bc.scanPath)
	if err != nil {
		return err
	}

	//commitId := metadata.GetCommitID(bc.scanPath)

	buildSystem := metadata.GetBuildSystem()

	if _, err := bc.client.UpdateSource(ctx, &securitycenter.UpdateSourceRequest{
		Source: &securitycenter.Source{
			//Name: fmt.Sprintf("%s (%s)", repoName, branch),
			DisplayName: fmt.Sprintf("%s (%s)", repoName, branch),
			Description: fmt.Sprintf("%s repository %s, branch %s", buildSystem, repoName, branch),
			//CanonicalName: fmt.Sprintf(),
		},
		UpdateMask: nil,
	}); err != nil {
		return errors.Wrap(err, "could not upload source to GCP SCC")
	}

	for _, result := range results {

		for _, vuln := range result.Vulnerabilities {

			if _, err := bc.client.UpdateFinding(ctx, &securitycenter.UpdateFindingRequest{
				Finding: &securitycenter.Finding{
					Name: vuln.Title,
					//Parent: "",
					//ResourceName: "",
					State:       securitycenter.Finding_ACTIVE,
					Category:    string(result.Class),
					ExternalUri: vuln.SeveritySource,
					//SourceProperties: nil,
					//SecurityMarks:    nil,
					//EventTime:        nil,
					//CreateTime:       nil,
					Severity: getSCCSeverity(vuln.Severity),
					//CanonicalName:    "",
				},
			}); err != nil {
				return errors.Wrap(err, "could not upload finding to GCP SCC")
			}

		}

	}

	return nil
}

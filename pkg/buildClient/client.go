package buildClient

import (
	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	"context"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/hazcod/trivy-plugin-scc/pkg/log"
)

type Client interface {
	Upload(report.Results, map[string]string) error
}

type SCCClient struct {
	client   *securitycenter.Client
	scanPath string
	repoId   string
}

func Get(scanPath string) (Client, error) {
	ctx := context.Background()

	log.Logger.Debugf("Logging in to CSPM")
	client, err := securitycenter.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not create scc client: %v", err)
	}

	return &SCCClient{
		client:   client,
		scanPath: scanPath,
	}, nil
}

package uploader

import (
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/hazcod/trivy-plugin-scc/pkg/buildClient"
	"github.com/hazcod/trivy-plugin-scc/pkg/log"
)

// Upload forwards the results to the configured client
func Upload(client buildClient.Client, results report.Results, tags map[string]string) error {
	log.Logger.Debugf("Uploading scan with tags. %v", tags)
	return client.Upload(results, tags)
}

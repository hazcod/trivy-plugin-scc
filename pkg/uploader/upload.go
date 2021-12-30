package uploader

import (
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/buildClient"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
)

// Upload forwards the results to the configured client
func Upload(client buildClient.Client, results report.Results, tags map[string]string) error {
	log.Logger.Debugf("Uploading scan with tags. %v", tags)
	return client.Upload(results, tags)
}

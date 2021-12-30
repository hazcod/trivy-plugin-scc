package test

import "github.com/aquasecurity/trivy/pkg/report"

type FakeClient struct {
}

func (f FakeClient) Upload(results report.Results, tags map[string]string) error {
	return nil
}

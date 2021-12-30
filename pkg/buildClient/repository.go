package buildClient

import (
	"github.com/hazcod/trivy-plugin-scc/pkg/metadata"
)

func (bc *SCCClient) getScmID() (string, error) {
	scmID, err := metadata.GetScmID(bc.scanPath)
	if err != nil {
		return "", err
	}

	return scmID, nil
}

func (bc *SCCClient) getRepoName() (string, error) {
	repoName, _, err := metadata.GetRepositoryDetails(bc.scanPath)
	if err != nil {
		return "", err
	}

	return repoName, nil
}

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/hazcod/trivy-plugin-scc/pkg/buildClient"
	"github.com/hazcod/trivy-plugin-scc/pkg/log"
	"github.com/hazcod/trivy-plugin-scc/pkg/scanner"
	"github.com/hazcod/trivy-plugin-scc/pkg/uploader"
	"github.com/spf13/cobra"
)

var (
	severities string
	debug      bool
	tags       map[string]string
)

func init() {
	rootCmd.PersistentFlags().StringVar(&severities, "severities", strings.Join(scanner.AllSeverities, ","), "Minimum severity to display misconfigurations for")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "v", false, "Display debug output")
	rootCmd.PersistentFlags().StringToStringVarP(&tags, "tags", "t", nil, "Add arbitrary tags to the scan; --tags key1=val1,key2=val2")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:          "scc <scanPath>",
	Short:        "Scan a filesystem location for vulnerabilities and config misconfiguration",
	Hidden:       true,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := log.InitLogger(debug, false); err != nil {
			return err
		}

		if err := verifySeverities(); err != nil {
			return err
		}

		scanPath, _ := os.Getwd()
		if len(args) > 0 {
			// when scan path provided, use that
			scanPath = args[0]
		}
		log.Logger.Debugf("Using scanPath %s", scanPath)

		client, err := buildClient.Get(scanPath)
		if err != nil {
			return err
		}

		results, err := scanner.Scan(scanPath, severities, debug)
		if err != nil {
			return err
		}

		if err := uploader.Upload(client, results, tags); err != nil {
			return err
		}

		return nil
		//return checkPolicyResults(results)
	},
	Args: cobra.ExactArgs(1),
}

func verifySeverities() error {

	if severities != "" {
		severities = strings.ToUpper(severities)
		sevList := strings.Split(severities, ",")
		for _, sev := range sevList {
			if !scanner.AllSeverities.Any(sev) {
				return fmt.Errorf("could not resolve the provided severity: %s\nOptions are: [%s]\n", sev, strings.Join(scanner.AllSeverities, ", "))
			}
		}
	}
	return nil
}

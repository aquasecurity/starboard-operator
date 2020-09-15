package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/starboard-operator/pkg/aqua/client"
	"github.com/aquasecurity/starboard-operator/pkg/aqua/scanner/api"
	"github.com/aquasecurity/starboard-operator/pkg/aqua/scanner/cli"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
)

const (
	hostFlag     = "host"
	userFlag     = "user"
	passwordFlag = "password"
)

type options struct {
	baseURL     string
	credentials client.UsernameAndPassword
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("error: %s", err.Error())
	}
}

func run() error {
	opt := options{}

	rootCmd := &cobra.Command{
		Use:           "scanner",
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := scan(opt, args[0])
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(report)
		},
	}

	rootCmd.Flags().StringVarP(&opt.baseURL, hostFlag, "H", "", "Aqua management console address (required)")
	rootCmd.Flags().StringVarP(&opt.credentials.Username, userFlag, "U", "", "Aqua management console username (required)")
	rootCmd.Flags().StringVarP(&opt.credentials.Password, passwordFlag, "P", "", "Aqua management console password (required)")

	_ = rootCmd.MarkFlagRequired(hostFlag)
	_ = rootCmd.MarkFlagRequired(userFlag)
	_ = rootCmd.MarkFlagRequired(passwordFlag)

	return rootCmd.Execute()
}

// scan scans the specified image reference. Firstly, attempt to download a vulnerability
// report with Aqua REST API call. If the report is not found, execute the `scannercli scan` command.
func scan(opt options, imageRef string) (report v1alpha1.VulnerabilityReport, err error) {
	clientset := client.NewClient(opt.baseURL, client.Authorization{
		Basic: &opt.credentials,
	})

	report, err = api.NewScanner(clientset).Scan(imageRef)
	if err == nil {
		return
	}
	if err != client.ErrNotFound {
		return
	}
	report, err = cli.NewScanner(opt.baseURL, opt.credentials).Scan(imageRef)
	if err != nil {
		return
	}
	return
}

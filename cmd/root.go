package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func Execute(version string) {
	rootCmd := newRootCmd(version)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd(version string) *cobra.Command {
	var (
		verbose bool
	)

	cmd := &cobra.Command{
		Use:           "scan4log4shell",
		Version:       version,
		Short:         "Scanner to detect vulnerable log4j versions on your file-system or to send specially crafted requests and catch callbacks of systems that are impacted by log4j log4shell vulnerability (CVE-2021-44228)",
		SilenceErrors: true,
	}

	cmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "print detailed logging messages")

	cmd.AddCommand(
		newLocalCmd(&verbose),
		newRemoteCmd(&verbose),
		newCompletionCmd(),
	)

	return cmd
}

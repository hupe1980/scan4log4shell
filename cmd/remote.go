package cmd

import "github.com/spf13/cobra"

func newRemoteCmd(noColor *bool, output *string, verbose *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "remote",
		Short:                 "Send specially crafted requests and catch callbacks of systems that are impacted by log4j log4shell vulnerability",
		SilenceUsage:          true,
		DisableFlagsInUseLine: true,
	}

	cmd.AddCommand(
		newRemoteCIDRCmd(noColor, output, verbose),
		newRemoteURLCmd(noColor, output, verbose),
	)

	return cmd
}

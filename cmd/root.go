package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	logFile = os.Stdout
	errFile = os.Stderr
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
		noColor bool
		verbose bool
		output  string
	)

	cmd := &cobra.Command{
		Use:           "scan4log4shell",
		Version:       version,
		Short:         "Scanner to detect vulnerable log4j versions on your file-system or to send specially crafted requests and catch callbacks of systems that are impacted by log4j log4shell vulnerability (CVE-2021-44228)",
		SilenceErrors: true,
	}

	cmd.PersistentFlags().BoolVarP(&noColor, "no-color", "", false, "disable color output")
	cmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "print detailed logging messages")
	cmd.PersistentFlags().StringVarP(&output, "output", "o", "", "output logfile name")

	cmd.AddCommand(
		newLocalCmd(&noColor, &output, &verbose),
		newRemoteCmd(&noColor, &output, &verbose),
		newCompletionCmd(),
	)

	return cmd
}

func printInfo(format string, a ...interface{}) {
	c := color.New(color.FgCyan)
	c.Fprintf(logFile, fmt.Sprintf("[i] %s\n", format), a...)
}

func printDanger(format string, a ...interface{}) {
	c := color.New(color.FgRed)
	c.Fprintf(logFile, fmt.Sprintf("[!] %s\n", format), a...)
}

func printError(format string, a ...interface{}) {
	c := color.New(color.FgHiRed)
	c.Fprintf(errFile, fmt.Sprintf("[x] %s\n", format), a...)
}

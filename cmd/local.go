package cmd

import (
	"log"
	"os"

	"github.com/hupe1980/log4shellscan/internal"
	"github.com/spf13/cobra"
)

type localOptions struct {
	excludes   []string
	ignoreExts []string
	ignoreV1   bool
	summary    bool
}

func newLocalCmd(output *string, verbose *bool) *cobra.Command {
	opts := &localOptions{}

	cmd := &cobra.Command{
		Use:           "local [paths]",
		Short:         "Detect vulnerable log4j versions on your file-system",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if *output != "" {
				f, err := os.Create(*output)
				if err != nil {
					return err
				}
				defer f.Close()
				log.SetOutput(f)
			}

			log.Printf("[i] Log4Shell CVE-2021-44228 Local Vulnerability Scan")

			results := []internal.Result{}

			for _, root := range args {
				log.Printf("[i] Start scanning path %s\n---------", root)

				r := internal.FilePathWalk(root, &internal.LocalOptions{
					Excludes:   opts.excludes,
					IgnoreExts: opts.ignoreExts,
					Verbose:    *verbose,
				})

				results = append(results, r...)
			}

			log.Printf("[i] Completed scanning")

			if opts.summary {
				log.Printf("[i] Summary")

				if len(results) == 0 {
					log.Printf("[i] No vulnable log4j version detected")
					return nil
				}

				for _, r := range results {
					log.Printf(r.Message)
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&opts.ignoreV1, "ignore-v1", "", false, "ignore log4j 1.x versions")
	cmd.Flags().BoolVarP(&opts.summary, "print-summary", "", false, "print a summary")
	cmd.Flags().StringArrayVarP(&opts.ignoreExts, "ignore-ext", "", []string{}, "ignore .jar | .zip | .war | .ear | .aar")
	cmd.Flags().StringArrayVarP(&opts.excludes, "exclude", "e", []string{}, "path to exclude")

	return cmd
}

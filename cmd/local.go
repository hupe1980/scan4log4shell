package cmd

import (
	"context"
	"io"
	"os"
	"sync"

	"github.com/fatih/color"
	"github.com/hupe1980/log4shellscan/internal"
	"github.com/spf13/cobra"
	"golang.org/x/sync/semaphore"
)

type localOptions struct {
	excludes   []string
	ignoreExts []string
	ignoreV1   bool
	maxThreads int
}

func newLocalCmd(noColor *bool, output *string, verbose *bool) *cobra.Command {
	opts := &localOptions{}

	cmd := &cobra.Command{
		Use:           "local [paths]",
		Short:         "Detect vulnerable log4j versions on your file-system",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if *output != "" {
				color.NoColor = true
				f, err := os.Create(*output)
				if err != nil {
					return err
				}
				defer f.Close()

				logFile = f
				errFile = f
			}

			if *noColor {
				color.NoColor = true
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var wg sync.WaitGroup
			sem := semaphore.NewWeighted(int64(opts.maxThreads))

			printInfo("Log4Shell CVE-2021-44228 Local Vulnerability Scan")

			scanner := internal.NewLocalScanner(&internal.LocalOptions{
				Excludes:   opts.excludes,
				IgnoreExts: opts.ignoreExts,
			})

			go func() {
				for hit := range scanner.Hits() {
					printDanger("Hit: %s", hit)
				}
			}()

			go func() {
				for err := range scanner.Errors() {
					printError("Error: %s", err)
				}
			}()

			for _, root := range args {
				if err := sem.Acquire(ctx, 1); err != nil {
					return err
				}
				wg.Add(1)
				go func(root string) {
					defer func() {
						wg.Done()
						sem.Release(1)
					}()
					scanner.ArchieveWalk(root, func(path string, ra io.ReaderAt, sz int64, opts *internal.LocalOptions) {
						if *verbose {
							printInfo("Inspecting %s", path)
						}

						scanner.InspectJar(path, ra, sz, opts)
					})
				}(root)
			}

			wg.Wait()

			printError("rererer")

			printInfo("Completed scanning")

			return nil
		},
	}

	cmd.Flags().BoolVarP(&opts.ignoreV1, "ignore-v1", "", false, "ignore log4j 1.x versions")
	cmd.Flags().StringArrayVarP(&opts.ignoreExts, "ignore-ext", "", []string{}, "ignore .jar | .zip | .war | .ear | .aar")
	cmd.Flags().StringArrayVarP(&opts.excludes, "exclude", "e", []string{}, "path to exclude")
	cmd.Flags().IntVarP(&opts.maxThreads, "max-threads", "", 5, "max number of concurrent threads")

	return cmd
}

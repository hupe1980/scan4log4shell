package cmd

import (
	"context"
	"io"
	"log"
	"os"
	"sync"

	"github.com/hupe1980/log4shellscan/internal"
	"github.com/spf13/cobra"
	"golang.org/x/sync/semaphore"
)

type localOptions struct {
	excludes   []string
	ignoreExts []string
	ignoreV1   bool
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

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var wg sync.WaitGroup
			sem := semaphore.NewWeighted(int64(2))

			log.Printf("[i] Log4Shell CVE-2021-44228 Local Vulnerability Scan")

			scanner := internal.NewLocalScanner(&internal.LocalOptions{
				Excludes:   opts.excludes,
				IgnoreExts: opts.ignoreExts,
			})

			go func() {
				for hit := range scanner.Hits() {
					log.Printf("[!] Hit: %s\n", hit)
				}
			}()

			go func() {
				for err := range scanner.Errors() {
					log.Printf("[x] Error: %s\n", err)
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
							log.Printf("[i] Inspecting %s\n", path)
						}

						scanner.InspectJar(path, ra, sz, opts)
					})
				}(root)
			}

			wg.Wait()

			log.Printf("[i] Completed scanning")

			return nil
		},
	}

	cmd.Flags().BoolVarP(&opts.ignoreV1, "ignore-v1", "", false, "ignore log4j 1.x versions")
	cmd.Flags().StringArrayVarP(&opts.ignoreExts, "ignore-ext", "", []string{}, "ignore .jar | .zip | .war | .ear | .aar")
	cmd.Flags().StringArrayVarP(&opts.excludes, "exclude", "e", []string{}, "path to exclude")

	return cmd
}

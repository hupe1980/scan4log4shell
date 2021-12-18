package cmd

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/hupe1980/log4shellscan/internal"
	"github.com/spf13/cobra"
	"golang.org/x/sync/semaphore"
)

type remoteCIDROptions struct {
	remoteOptions
	schema string
	ports  []string
}

func newRemoteCIDRCmd(noColor *bool, output *string, verbose *bool) *cobra.Command {
	opts := &remoteCIDROptions{}

	cmd := &cobra.Command{
		Use:           "cidr [cidr]",
		Short:         "Send specially crafted requests to a cidr",
		Args:          cobra.MinimumNArgs(1),
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

			cidr := args[0]

			printInfo("Log4Shell CVE-2021-44228 Remote Vulnerability Scan")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var wg sync.WaitGroup
			sem := semaphore.NewWeighted(int64(opts.maxThreads))

			remoteOpts := &internal.RemoteOptions{
				CADDR:              opts.caddr,
				RequestType:        opts.requestType,
				NoUserAgentFuzzing: opts.noUserAgentFuzzing,
				NoRedirect:         opts.noRedirect,
				WafBypass:          opts.wafBypass,
				HeadersFile:        opts.headersFile,
				FieldsFile:         opts.fieldsFile,
				PayLoadsFile:       opts.payloadsFile,
				Timeout:            opts.timeout,
				CheckCVE2021_45046: opts.checkCVE2021_45046,
			}

			if opts.proxy != "" {
				proxyURL, err := url.Parse(opts.proxy)
				if err != nil {
					return err
				}
				remoteOpts.Proxies = []*url.URL{proxyURL}
			}

			if opts.listen {
				catcher, err := internal.NewCallBackCatcher("tcp", opts.caddr)
				if err != nil {
					return err
				}
				defer catcher.Close()

				catcher.Handler(func(addr *net.TCPAddr) {
					printDanger("Possibly vulnerable host identified: %v:%d", addr.IP.String(), addr.Port)
				})

				printInfo("Listening on %s", opts.caddr)

				go func() {
					err := catcher.Listen(ctx)
					if err != nil {
						printError("cannot start callback catcher: %s", err)
						os.Exit(1)
					}
				}()
			}

			printInfo("Start scanning CIDR %s\n---------", cidr)

			scanner, err := internal.NewRemoteScanner(remoteOpts)
			if err != nil {
				return err
			}

			if opts.authFuzzing {
				scanner.StatusCodeHandler(http.StatusUnauthorized, unauthorizedHandler(*verbose))
			}

			if opts.submitForms {
				scanner.StatusCodeHandler(http.StatusOK, submitFormHanlder(*verbose))
			}

			errs := make(chan error)

			if err := scanner.CIDRWalk(cidr, opts.schema, opts.ports, func(url, payload string) error {
				if err := sem.Acquire(ctx, 1); err != nil {
					return err
				}

				if *verbose {
					printInfo("Checking %s for %s", payload, url)
				}

				wg.Add(1)

				go func() {
					defer func() {
						wg.Done()
						sem.Release(1)
					}()

					if err := scanner.Scan(ctx, opts.requestType, url, payload); err != nil {
						errs <- err
					}
				}()
				return nil
			}); err != nil {
				return err
			}

			go func() {
				wg.Wait()
				close(errs)
			}()

			// return the first error
			for err := range errs {
				if err != nil {
					return err
				}
			}

			printInfo("Completed scanning of CIDR %s", cidr)
			if opts.listen {
				printInfo("[i] Waiting for incoming callbacks!")
				printInfo("[i] Use ctrl+c to stop the program.")

				signalChan := make(chan os.Signal, 1)
				signal.Notify(signalChan, os.Interrupt)

				if opts.noWaitTimeout {
					<-signalChan
				} else {
					select {
					case <-signalChan:
					case <-time.After(opts.wait):
					}
				}
			}

			return nil
		},
	}

	addRemoteFlags(cmd, &opts.remoteOptions)
	cmd.Flags().StringVarP(&opts.schema, "schema", "", "https", "schema to use for requests")
	cmd.Flags().StringArrayVarP(&opts.ports, "port", "p", []string{"8080"}, "port to scan")

	return cmd
}

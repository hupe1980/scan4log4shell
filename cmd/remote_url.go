package cmd

import (
	"context"
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

type remoteURLOptions struct {
	remoteOptions
}

func newRemoteURLCmd(noColor *bool, output *string, verbose *bool) *cobra.Command {
	opts := &remoteURLOptions{}

	cmd := &cobra.Command{
		Use:           "url [url]",
		Short:         "Send specially crafted requests to an url",
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

			targetURL := args[0]

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

			if opts.catcherType != noCatcher {
				catcher, err := newCatcher(opts.catcherType, opts.caddr)
				if err != nil {
					return err
				}
				defer catcher.Close()

				remoteOpts.CADDR = catcher.Addr()

				catcher.Handler(func(remoteAddr string) {
					printDanger("Possibly vulnerable host identified: %v", remoteAddr)
				})

				printInfo("Listening on %s", catcher.Addr())
				go func() {
					err := catcher.Listen(ctx)
					if err != nil {
						printError("cannot start callback catcher: %s", err)
						os.Exit(1)
					}
				}()
			}

			printInfo("Start scanning CIDR %s\n---------", targetURL)

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

			for _, payload := range scanner.Payloads() {
				if err := sem.Acquire(ctx, 1); err != nil {
					return err
				}

				if *verbose {
					printInfo("Checking %s for %s", payload, targetURL)
				}

				wg.Add(1)

				go func(payload string) {
					defer func() {
						wg.Done()
						sem.Release(1)
					}()

					if err := scanner.Scan(ctx, opts.requestType, targetURL, payload); err != nil {
						errs <- err
					}
				}(payload)
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

			printInfo("Completed scanning of CIDR %s", targetURL)
			if opts.catcherType != noCatcher {
				printInfo("Waiting for incoming callbacks!")
				printInfo("Use ctrl+c to stop the program.")

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

	return cmd
}

package cmd

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
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
		Use:   "cidr [cidr]",
		Short: "Send specially crafted requests to a cidr",
		Args:  cobra.MinimumNArgs(1),
		Example: `- Scan a complete cidr: scan4log4shell remote cidr 172.20.0.0/24
- TCP catcher: scan4log4shell remote cidr 172.20.0.0/24 --catcher-type tcp --caddr 172.20.0.30:4444
- Custom headers file: scan4log4shell remote cidr 172.20.0.0/24 --headers-file ./headers.txt
- Run all tests: scan4log4shell remote cidr 172.20.0.0/24 -a`,
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

			printInfo("Log4Shell Remote Vulnerability Scan")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var wg sync.WaitGroup
			sem := semaphore.NewWeighted(int64(opts.maxThreads))

			allChecksShortcut(&opts.remoteOptions)

			remoteOpts := &internal.RemoteOptions{
				BasicAuth:          opts.basicAuth,
				CADDR:              opts.caddr,
				Resource:           opts.resource,
				RequestTypes:       opts.requestTypes,
				NoUserAgentFuzzing: opts.noUserAgentFuzzing,
				NoRedirect:         opts.noRedirect,
				WafBypass:          opts.wafBypass,
				HeadersFile:        opts.headersFile,
				Headers:            opts.headers,
				HeaderValues:       opts.headerValues,
				FieldsFile:         opts.fieldsFile,
				Fields:             opts.fields,
				FieldValues:        opts.fieldValues,
				PayLoadsFile:       opts.payloadsFile,
				Payloads:           opts.payloads,
				ParamsFile:         opts.paramsFile,
				Params:             opts.params,
				ParamValues:        opts.paramValues,
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
				catcher, err := newCatcher(strings.ToLower(opts.catcherType), opts.caddr)
				if err != nil {
					return err
				}
				defer catcher.Close()

				remoteOpts.CADDR = catcher.Addr()

				catcher.Handler(func(remoteAddr, resource string) {
					printDanger("Possibly vulnerable host identified: %v/%s", remoteAddr, resource)
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

			printInfo("Start scanning CIDR %s", cidr)

			scanner, err := internal.NewRemoteScanner(remoteOpts)
			if err != nil {
				return err
			}

			if opts.authFuzzing {
				scanner.StatusCodeHandler(http.StatusUnauthorized, unauthorizedHandler(*verbose))
			}

			if opts.formFuzzing {
				scanner.StatusCodeHandler(http.StatusOK, submitFormHanlder(*verbose))
			}

			errs := make(chan error)

			if err := scanner.CIDRWalk(cidr, opts.schema, opts.ports, func(method, url, payload string) error {
				if err := sem.Acquire(ctx, 1); err != nil {
					return err
				}

				if *verbose {
					printInfo("Checking %s for %s [%s]", payload, url, strings.ToUpper(method))
				}

				wg.Add(1)

				go func() {
					defer func() {
						wg.Done()
						sem.Release(1)
					}()

					if err := scanner.Scan(ctx, method, url, payload); err != nil {
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
	cmd.Flags().StringVarP(&opts.schema, "schema", "", "https", "schema to use for requests")
	cmd.Flags().StringSliceVarP(&opts.ports, "port", "p", []string{"8080"}, "port to scan")

	return cmd
}

package cmd

import (
	"bufio"
	"context"
	"errors"
	"io"
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

type remoteURLOptions struct {
	remoteOptions
}

func newRemoteURLCmd(noColor *bool, output *string, verbose *bool) *cobra.Command {
	opts := &remoteURLOptions{}

	cmd := &cobra.Command{
		Use:   "url [urls]",
		Short: "Send specially crafted requests to an url",
		Example: `- Scan a url: scan4log4shell remote url https://target.org
- Scan multiple urls: scan4log4shell remote url https://target1.org https://target2.org
- Scan multiple urls: cat targets.txt | scan4log4shell remote url
- TCP catcher: scan4log4shell remote url https://target.org --catcher-type tcp --caddr 172.20.0.30:4444
- Custom headers file: scan4log4shell remote url https://target.org --headers-file ./headers.txt
- Scan url behind basic auth: scan4log4shell remote url https://target.org --basic-auth user:pass
- Run all tests: scan4log4shell remote url https://target.org -a`,
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

			target, err := newTarget(args)
			if err != nil {
				return err
			}

			for targetURL := range target.URL() {
				printInfo("Start scanning URL %s", targetURL)

				for _, payload := range scanner.Payloads() {
					for _, method := range opts.requestTypes {
						if err := sem.Acquire(ctx, 1); err != nil {
							return err
						}

						if *verbose {
							printInfo("Checking %s for %s [%s]", payload, targetURL, strings.ToUpper(method))
						}

						wg.Add(1)

						go func(method, targetURL, payload string) {
							defer func() {
								wg.Done()
								sem.Release(1)
							}()

							if err := scanner.Scan(ctx, strings.ToLower(method), targetURL, payload); err != nil {
								errs <- err
							}
						}(method, targetURL, payload)
					}
				}

				printInfo("All request to %s have been sent", targetURL)
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

			printInfo("Completed scanning")
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

type target struct {
	reader io.Reader
}

func newTarget(args []string) (*target, error) {
	r, err := newTargetReader(args)
	if err != nil {
		return nil, err
	}

	return &target{
		reader: r,
	}, nil
}

func (t *target) URL() <-chan string {
	br := bufio.NewScanner(t.reader)

	url := make(chan string)

	go func() {
		for br.Scan() {
			url <- br.Text()
		}
		close(url)
	}()

	return url
}

func newTargetReader(args []string) (io.Reader, error) {
	switch {
	case len(args) != 0:
		return strings.NewReader(strings.Join(args, "\n")), nil
	case hasStdin():
		return os.Stdin, nil
	default:
		return nil, errors.New("no target data")
	}
}

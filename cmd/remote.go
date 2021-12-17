package cmd

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/hupe1980/log4shellscan/internal"
	"github.com/spf13/cobra"
	"golang.org/x/sync/semaphore"
)

type remoteOptions struct {
	schema             string
	caddr              string
	cidr               string
	ports              []string
	requestType        string
	proxy              string
	listen             bool
	noUserAgentFuzzing bool
	noBasicAuthFuzzing bool
	noRedirect         bool
	noWaitTimeout      bool
	wafBypass          bool
	timeout            time.Duration
	wait               time.Duration
	headersFile        string
	fieldsFile         string
	payloadsFile       string
	maxThreads         int
}

func newRemoteCmd(output *string, verbose *bool) *cobra.Command {
	opts := &remoteOptions{}

	cmd := &cobra.Command{
		Use:           "remote",
		Short:         "Send specially crafted requests and catch callbacks of systems that are impacted by log4j log4shell vulnerability",
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

			log.Printf("[i] Log4Shell CVE-2021-44228 Remote Vulnerability Scan")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var wg sync.WaitGroup
			sem := semaphore.NewWeighted(int64(opts.maxThreads))

			remoteOpts := &internal.RemoteOptions{
				Schema:             opts.schema,
				CADDR:              opts.caddr,
				Ports:              opts.ports,
				RequestType:        opts.requestType,
				NoUserAgentFuzzing: opts.noUserAgentFuzzing,
				NoBasicAuthFuzzing: opts.noBasicAuthFuzzing,
				NoRedirect:         opts.noRedirect,
				WafBypass:          opts.wafBypass,
				HeadersFile:        opts.headersFile,
				FieldsFile:         opts.fieldsFile,
				PayLoadsFile:       opts.payloadsFile,
				Timeout:            opts.timeout,
			}

			if opts.proxy != "" {
				proxyURL, err := url.Parse(opts.proxy)
				if err != nil {
					return err
				}
				remoteOpts.Proxies = []*url.URL{proxyURL}
			}

			if opts.listen {
				wg.Add(1)
				go internal.CatchCallbacks(ctx, &wg, remoteOpts)
			}

			// waiting for starting catcher
			wg.Wait()

			log.Printf("[i] Start scanning CIDR %s\n---------", opts.cidr)

			scanner, err := internal.NewRemoteScanner(remoteOpts)
			if err != nil {
				return err
			}

			scanner.StatusCodeHandler(http.StatusUnauthorized, func(client *http.Client, resp *http.Response, req *http.Request, payload string, opts *internal.RemoteOptions) {
				if !opts.NoBasicAuthFuzzing {
					auth := resp.Header.Get("WWW-Authenticate")

					if strings.HasPrefix(auth, "Basic") {
						if *verbose {
							log.Printf("[i] Checking %s for %s with basic auth\n", payload, req.URL.String())
						}

						req.SetBasicAuth(payload, payload)

						resp, err := client.Do(req)
						if err != nil {
							// ignore
							return
						}

						resp.Body.Close()
					}
				}
			})

			errs := make(chan error)

			if err := scanner.CIDRWalk(opts.cidr, func(url, payload string) error {
				if err := sem.Acquire(ctx, 1); err != nil {
					return err
				}

				if *verbose {
					log.Printf("[i] Checking %s for %s \n", payload, url)
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

			log.Printf("[i] Completed scanning of CIDR %s\n", opts.cidr)
			if opts.listen {
				log.Println("[i] Waiting for incoming callbacks!")
				log.Println("[i] Use ctrl+c to stop the program.")

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

	cmd.Flags().StringVarP(&opts.headersFile, "headers-file", "", "", "use custom headers from file")
	cmd.Flags().StringVarP(&opts.fieldsFile, "fields-file", "", "", "use custom field from file")
	cmd.Flags().StringVarP(&opts.payloadsFile, "payloads-file", "", "", "use custom payloads from file")
	cmd.Flags().StringVarP(&opts.schema, "schema", "", "https", "schema to use for requests")
	cmd.Flags().StringVarP(&opts.caddr, "caddr", "", "", "address to catch the callbacks (eg. ip:port)")
	cmd.Flags().StringVarP(&opts.cidr, "cidr", "", "192.168.1.0/28", "subnet to scan")
	cmd.Flags().StringArrayVarP(&opts.ports, "port", "p", []string{"8080"}, "port to scan")
	cmd.Flags().StringVarP(&opts.requestType, "type", "t", "get", "get, post or json")
	cmd.Flags().StringVarP(&opts.proxy, "proxy", "", "", "proxy url")
	cmd.Flags().BoolVarP(&opts.listen, "listen", "", false, "start a listener to catch callbacks")
	cmd.Flags().BoolVarP(&opts.noUserAgentFuzzing, "no-user-agent-fuzzing", "", false, "exclude user-agent header from fuzzing")
	cmd.Flags().BoolVarP(&opts.noBasicAuthFuzzing, "no-basic-auth-fuzzing", "", false, "exclude basic auth from fuzzing")
	cmd.Flags().BoolVarP(&opts.noRedirect, "no-redirect", "", false, "do not follow redirects")
	cmd.Flags().BoolVarP(&opts.noWaitTimeout, "no-wait-timeout", "", false, "wait forever for callbacks")
	cmd.Flags().BoolVarP(&opts.wafBypass, "waf-bypass", "", false, "extend scans with WAF bypass payload ")
	cmd.Flags().DurationVarP(&opts.wait, "wait", "w", 5*time.Second, "wait time to catch callbacks")
	cmd.Flags().DurationVarP(&opts.timeout, "timeout", "", 3*time.Second, "time limit for requests")
	cmd.Flags().IntVarP(&opts.maxThreads, "max-threads", "", 150, "max number of concurrent threads")

	return cmd
}

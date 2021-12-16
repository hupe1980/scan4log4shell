package cmd

import (
	"context"
	"log"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/hupe1980/log4shellscan/internal"
	"github.com/spf13/cobra"
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

			remoteOpts := &internal.RemoteOptions{
				Schema:             opts.schema,
				CADDR:              opts.caddr,
				CIDR:               opts.cidr,
				Ports:              opts.ports,
				RequestType:        opts.requestType,
				Listen:             opts.listen,
				NoUserAgentFuzzing: opts.noUserAgentFuzzing,
				NoRedirect:         opts.noRedirect,
				WafBypass:          opts.wafBypass,
				Verbose:            *verbose,
				HeadersFile:        opts.headersFile,
				FieldsFile:         opts.fieldsFile,
				PayLoadsFile:       opts.payloadsFile,
				Timeout:            opts.timeout,
				MaxThreads:         opts.maxThreads,
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

			err := internal.Request(ctx, remoteOpts)
			if err != nil {
				return err
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

			cancel()

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
	cmd.Flags().BoolVarP(&opts.noRedirect, "no-redirect", "", false, "do not follow redirects")
	cmd.Flags().BoolVarP(&opts.noWaitTimeout, "no-wait-timeout", "", false, "wait forever for callbacks")
	cmd.Flags().BoolVarP(&opts.wafBypass, "waf-bypass", "", false, "extend scans with WAF bypass payload ")
	cmd.Flags().DurationVarP(&opts.wait, "wait", "w", 5*time.Second, "wait time to catch callbacks")
	cmd.Flags().DurationVarP(&opts.timeout, "timeout", "", 3*time.Second, "time limit for requests")
	cmd.Flags().IntVarP(&opts.maxThreads, "max-threads", "", 50, "max number of concurrent threads")

	return cmd
}

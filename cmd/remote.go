package cmd

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hupe1980/log4shellscan/internal"
	"github.com/spf13/cobra"
	"golang.org/x/net/html"
)

type remoteOptions struct {
	caddr              string
	requestType        string
	proxy              string
	listen             bool
	noUserAgentFuzzing bool
	basicAuthFuzzing   bool
	submitForms        bool
	noRedirect         bool
	noWaitTimeout      bool
	wafBypass          bool
	timeout            time.Duration
	wait               time.Duration
	headersFile        string
	headers            []string
	fieldsFile         string
	fields             []string
	payloadsFile       string
	payloads           []string
	maxThreads         int
	checkCVE2021_45046 bool
}

func newRemoteCmd(noColor *bool, output *string, verbose *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "remote",
		Short:                 "Send specially crafted requests and catch callbacks of systems that are impacted by log4j log4shell vulnerability",
		SilenceUsage:          true,
		DisableFlagsInUseLine: true,
	}

	cmd.AddCommand(
		newRemoteCIDRCmd(noColor, output, verbose),
		newRemoteURLCmd(noColor, output, verbose),
	)

	return cmd
}

func addRemoteFlags(cmd *cobra.Command, opts *remoteOptions) {
	cmd.Flags().StringVarP(&opts.headersFile, "headers-file", "", "", "use custom headers from file")
	cmd.Flags().StringVarP(&opts.fieldsFile, "fields-file", "", "", "use custom field from file")
	cmd.Flags().StringVarP(&opts.payloadsFile, "payloads-file", "", "", "use custom payloads from file")
	cmd.Flags().StringVarP(&opts.caddr, "caddr", "", "", "address to catch the callbacks (eg. ip:port)")
	cmd.Flags().StringVarP(&opts.requestType, "type", "t", "get", "get, post or json")
	cmd.Flags().StringVarP(&opts.proxy, "proxy", "", "", "proxy url")
	cmd.Flags().BoolVarP(&opts.listen, "listen", "", false, "start a listener to catch callbacks")
	cmd.Flags().BoolVarP(&opts.noUserAgentFuzzing, "no-user-agent-fuzzing", "", false, "exclude user-agent header from fuzzing")
	cmd.Flags().BoolVarP(&opts.basicAuthFuzzing, "basic-auth-fuzzing", "", false, "add basic auth to fuzzing")
	cmd.Flags().BoolVarP(&opts.submitForms, "submit-forms", "", false, "add form submits to fuzzing")
	cmd.Flags().BoolVarP(&opts.noRedirect, "no-redirect", "", false, "do not follow redirects")
	cmd.Flags().BoolVarP(&opts.noWaitTimeout, "no-wait-timeout", "", false, "wait forever for callbacks")
	cmd.Flags().BoolVarP(&opts.wafBypass, "waf-bypass", "", false, "extend scans with WAF bypass payload ")
	cmd.Flags().DurationVarP(&opts.wait, "wait", "w", 5*time.Second, "wait time to catch callbacks")
	cmd.Flags().DurationVarP(&opts.timeout, "timeout", "", 3*time.Second, "time limit for requests")
	cmd.Flags().IntVarP(&opts.maxThreads, "max-threads", "", 150, "max number of concurrent threads")
	cmd.Flags().BoolVarP(&opts.checkCVE2021_45046, "check-cve-2021-45046", "", false, "check for CVE-2021-45046")
	cmd.Flags().StringArrayVarP(&opts.headers, "header", "", []string{""}, "header to use")
	cmd.Flags().StringArrayVarP(&opts.fields, "field", "", []string{""}, "field to use")
	cmd.Flags().StringArrayVarP(&opts.payloads, "payload", "", []string{""}, "payload to use")
}

var unauthorizedHandler = func(verbose bool) internal.StatusCodeHandlerFunc {
	return func(ctx context.Context, client *http.Client, resp *http.Response, req *http.Request, payload string, opts *internal.RemoteOptions) {
		auth := resp.Header.Get("WWW-Authenticate")

		if strings.HasPrefix(auth, "Basic") {
			if verbose {
				printInfo("Checking %s for %s with basic auth\n", payload, req.URL.String())
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
}

var submitFormHanlder = func(verbose bool) internal.StatusCodeHandlerFunc {
	return func(ctx context.Context, client *http.Client, resp *http.Response, req *http.Request, payload string, opts *internal.RemoteOptions) {
		root, err := html.Parse(resp.Body)
		if err != nil {
			//ignore
			return
		}

		forms := internal.ParseForms(root)
		if len(forms) == 0 {
			if verbose {
				printInfo("No forms found in response from %s/%s", req.URL.Host, req.URL.Path)
			}
			return
		}

		var wg sync.WaitGroup

		for _, form := range forms {
			wg.Add(1)

			go func(form internal.HTMLForm) {
				defer wg.Done()

				actionURL, err := url.Parse(form.Action)
				if err != nil {
					return
				}

				for k := range form.Values {
					form.Values.Set(k, payload)
				}

				actionURL = resp.Request.URL.ResolveReference(actionURL)

				if actionURL.Hostname() != req.URL.Host {
					if verbose {
						printInfo("Hostname %s out of scope", actionURL.Hostname())
					}

					return
				}

				submitReq, err := http.NewRequestWithContext(ctx, form.Method, actionURL.String(), strings.NewReader(form.Values.Encode()))
				if err != nil {
					return
				}

				submitReq.Header = req.Header

				if verbose {
					printInfo("Checking %s for %s", payload, actionURL)
				}

				resp, err := client.Do(req)
				//resp, err = client.PostForm(actionURL.String(), form.Values)
				if err != nil {
					// ignore
					return
				}

				resp.Body.Close()
			}(form)
		}

		wg.Wait()
	}
}

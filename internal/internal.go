package internal

import (
	"embed"
	"net/url"
	"path/filepath"
	"time"
)

//go:embed resource
var f embed.FS

type RemoteOptions struct {
	Schema             string
	CADDR              string
	Ports              []string
	RequestType        string
	Proxies            []*url.URL
	NoUserAgentFuzzing bool
	NoBasicAuthFuzzing bool
	NoRedirect         bool
	WafBypass          bool
	HeadersFile        string
	FieldsFile         string
	PayLoadsFile       string
	Timeout            time.Duration
}

type LocalOptions struct {
	Excludes   []string
	IgnoreExts []string
	IgnoreV1   bool
}

type Result struct {
	Identifier string
	Message    string
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}

	return false
}

func absFilepath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}

	return path
}

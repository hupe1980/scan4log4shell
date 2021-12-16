package internal

import (
	"embed"
	"net/url"
	"path/filepath"
)

//go:embed resource
var f embed.FS

type RemoteOptions struct {
	Schema             string
	CADDR              string
	CIDR               string
	Ports              []string
	RequestType        string
	Proxies            []*url.URL
	Listen             bool
	NoUserAgentFuzzing bool
	WafBypass          bool
	Verbose            bool
}

type LocalOptions struct {
	Roots      []string
	Excludes   []string
	IgnoreExts []string
	IgnoreV1   bool
	Verbose    bool
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

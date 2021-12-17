package internal

import (
	"embed"
	"path/filepath"
)

//go:embed resource
var f embed.FS

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

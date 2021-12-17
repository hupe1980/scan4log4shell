package internal

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type LocalOptions struct {
	Excludes           []string
	IgnoreExts         []string
	IgnoreV1           bool
	ShowSafe           bool
	CheckCVE2021_45046 bool
}
type LocalScanner struct {
	opts      *LocalOptions
	hitsChan  chan string
	infosChan chan string
	errsChan  chan error
}

func NewLocalScanner(opts *LocalOptions) *LocalScanner {
	return &LocalScanner{
		opts:      opts,
		hitsChan:  make(chan string),
		infosChan: make(chan string),
		errsChan:  make(chan error),
	}
}

func (ls *LocalScanner) Hits() <-chan string {
	return ls.hitsChan
}

func (ls *LocalScanner) Infos() <-chan string {
	return ls.infosChan
}

func (ls *LocalScanner) Errors() <-chan error {
	return ls.errsChan
}

func (ls *LocalScanner) ArchieveWalk(root string, fn func(path string, ra io.ReaderAt, sz int64, opts *LocalOptions)) {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			ls.errsChan <- fmt.Errorf("%s: %s", path, err)
			return nil
		}
		if len(ls.opts.Excludes) > 0 {
			for _, e := range ls.opts.Excludes {
				if match, _ := filepath.Match(e, path); match {
					return filepath.SkipDir
				}
			}
		}
		if info.IsDir() {
			return nil
		}
		switch ext := strings.ToLower(filepath.Ext(path)); ext {
		case ".jar", ".war", ".ear", ".zip", ".aar":
			if contains(ls.opts.IgnoreExts, ext) {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				ls.errsChan <- fmt.Errorf("cannot open %s: %v", path, err)
				return nil
			}
			defer f.Close()

			sz, err := f.Seek(0, os.SEEK_END)
			if err != nil {
				ls.errsChan <- fmt.Errorf("cannot seek in %s: %v", path, err)
				return nil
			}

			fn(path, f, sz, ls.opts)
		default:
			return nil
		}
		return nil
	})
}

func (ls *LocalScanner) InspectJar(path string, ra io.ReaderAt, sz int64, opts *LocalOptions) {
	zr, err := zip.NewReader(ra, sz)
	if err != nil {
		ls.errsChan <- fmt.Errorf("cannot open JAR file: %s (size %d): %v", path, sz, err)
		return
	}

	for _, file := range zr.File {
		switch strings.ToLower(filepath.Ext(file.Name)) {
		case ".class":
			if !opts.IgnoreV1 && strings.HasSuffix(file.Name, "log4j/FileAppender.class") {
				ls.hitsChan <- fmt.Sprintf("log4j V1 identified: %s", absFilepath(path))
				return
			}

			if strings.HasSuffix(file.Name, "core/lookup/JndiLookup.class") {
				if found := ls.lookupVulnJNDIManager(path, zr.File); found {
					ls.hitsChan <- fmt.Sprintf("possibly CVE-2021-44228 vulnerable file identified: %s", absFilepath(path))
				}

				return
			}

		case ".jar", ".war", ".ear", ".zip", ".aar":
			buf, err := readArchiveMember(file)
			if err != nil {
				ls.errsChan <- fmt.Errorf("cannot read JAR file member: %s (%s): %v", path, file.Name, err)
				return
			}

			ls.InspectJar(fmt.Sprintf("%s::%s", path, file.Name), bytes.NewReader(buf), int64(len(buf)), opts)
		}
	}
}

func (ls *LocalScanner) lookupVulnJNDIManager(path string, zip []*zip.File) bool {
	for _, file := range zip {
		if strings.ToLower(filepath.Ext(file.Name)) == ".class" {
			if strings.HasSuffix(file.Name, "core/net/JndiManager.class") {
				buf, err := readArchiveMember(file)
				if err != nil {
					ls.errsChan <- fmt.Errorf("cannot read JAR file member: %s (%s): %v", path, file.Name, err)
					return false
				}

				// v2.16.0
				if bytes.Contains(buf, []byte("log4j2.enableJndi")) {
					if ls.opts.ShowSafe {
						ls.infosChan <- fmt.Sprintf("log4j >= v2.16.0 detected: %s", path)
					}

					return false
				}

				// v2.15.0
				if bytes.Contains(buf, []byte("Invalid JNDI URI - {}")) {
					if ls.opts.CheckCVE2021_45046 {
						ls.hitsChan <- fmt.Sprintf("possibly CVE-2021-45046 vulnerable file identified: %s", absFilepath(path))
					} else if ls.opts.ShowSafe {
						ls.infosChan <- fmt.Sprintf("log4j v2.15.0 detected: %s", path)
					}

					return false
				}

				return true
			}
		}
	}

	return false
}

func readArchiveMember(file *zip.File) ([]byte, error) {
	fr, err := file.Open()
	if err != nil {
		return nil, err
	}

	buf, err := ioutil.ReadAll(fr)
	fr.Close()

	if err != nil {
		return nil, err
	}

	return buf, nil
}

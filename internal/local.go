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

type localScanState struct {
	isLog4J1                        bool
	log4jIndicator                  int
	hasJndiLookup                   bool
	hasJndiManager                  bool
	hasCVE2021_44228VulnJndiManager bool
	hasCVE2021_45046VulnJndiManager bool
}

func (ls *LocalScanner) InspectJar(path string, ra io.ReaderAt, sz int64, opts *LocalOptions) {
	zr, err := zip.NewReader(ra, sz)
	if err != nil {
		ls.errsChan <- fmt.Errorf("cannot open JAR file: %s (size %d): %v", path, sz, err)
		return
	}

	state := localScanState{}

LOOP:
	for _, file := range zr.File {
		switch strings.ToLower(filepath.Ext(file.Name)) {
		case ".class":
			if hasSuffix(file.Name, "log4j/DailyRollingFileAppender.class") {
				state.isLog4J1 = true
				break LOOP
			}

			if hasSuffix(file.Name, "core/lookup/JndiLookup.class") {
				state.hasJndiLookup = true
				continue
			}

			if hasSuffix(file.Name, "core/net/JndiManager.class") {
				state.hasJndiManager = true
				state.hasCVE2021_44228VulnJndiManager = true

				buf, err := readArchiveMember(file)
				if err != nil {
					ls.errsChan <- fmt.Errorf("cannot read JAR file member: %s (%s): %v", path, file.Name, err)
					return
				}

				if bytes.Contains(buf, []byte("log4j2.enableJndi")) { // v2.16.0
					state.hasCVE2021_44228VulnJndiManager = false
					state.hasCVE2021_45046VulnJndiManager = false
				} else if bytes.Contains(buf, []byte("Invalid JNDI URI - {}")) { // v2.15.0
					state.hasCVE2021_44228VulnJndiManager = false
					state.hasCVE2021_45046VulnJndiManager = true
				}
				continue
			}

			if hasSuffix(file.Name, "core/LogEvent.class") {
				state.log4jIndicator++
				continue
			}

			if hasSuffix(file.Name, "core/Appender.class") {
				state.log4jIndicator++
				continue
			}

			if hasSuffix(file.Name, "core/Filter.class") {
				state.log4jIndicator++
				continue
			}

			if hasSuffix(file.Name, "core/Layout.class") {
				state.log4jIndicator++
				continue
			}

			if hasSuffix(file.Name, "core/LoggerContext.class") {
				state.log4jIndicator++
				continue
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

	if !opts.IgnoreV1 && state.isLog4J1 {
		ls.hitsChan <- fmt.Sprintf("log4j V1 identified: %s", absFilepath(path))
		return
	}

	if state.hasJndiLookup && state.hasCVE2021_44228VulnJndiManager {
		ls.hitsChan <- fmt.Sprintf("possibly CVE-2021-44228 vulnerable file identified: %s", absFilepath(path))
		return
	}

	if ls.opts.CheckCVE2021_45046 && state.hasCVE2021_45046VulnJndiManager {
		ls.hitsChan <- fmt.Sprintf("possibly CVE-2021-45046 vulnerable file identified: %s", absFilepath(path))
		return
	}

	if state.log4jIndicator > 4 && state.hasJndiLookup && !state.hasJndiManager {
		ls.hitsChan <- fmt.Sprintf("possibly CVE-2021-44228 vulnerable file identified: %s", absFilepath(path))
		return
	}
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

func hasSuffix(fileName, suffix string) bool {
	return strings.HasSuffix(strings.ToLower(fileName), strings.ToLower(suffix))
}

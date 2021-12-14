package main

import (
	"context"
	"embed"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
)

// nolint: gochecknoglobals
var version = "dev"

//go:embed resource
var f embed.FS

type config struct {
	schema             string
	caddr              string
	cidr               string
	ports              string
	listen             bool
	noUserAgentFuzzing bool
	wafBypass          bool
}

func main() {
	cfg := &config{}

	flag.StringVar(&cfg.caddr, "caddr", "", "address to catch the callbacks (eg. ip:port)")
	flag.StringVar(&cfg.schema, "schema", "https", "schema to use for requests")
	flag.StringVar(&cfg.cidr, "cidr", "192.168.1.0/28", "subnet to scan (default 192.168.1.0/28)")
	flag.StringVar(&cfg.ports, "ports", "8080", "ports (comma separated) to scan (default 8080)")
	flag.BoolVar(&cfg.listen, "listen", false, "start a listener to catch callbacks (default false)")
	flag.BoolVar(&cfg.noUserAgentFuzzing, "no-user-agent-fuzzing", false, "exclude User-Agent header from fuzzing (default false)")
	flag.BoolVar(&cfg.wafBypass, "waf-bypass", false, "extend scans with WAF bypass payload (default false)")

	flag.Parse()

	log.Printf("[i] Log4Shell CVE-2021-44228 Vulnerability Scanner %s", version)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	if cfg.listen {
		wg.Add(1)
		go startCatcher(ctx, cfg, &wg)
	}

	// waiting for catcher
	wg.Wait()

	err := request(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	<-signalChan

	cancel()

	log.Printf("[i] Bye")
}

package internal

import (
	"context"
	"log"
	"net"
	"os"
	"sync"
)

func CatchCallbacks(ctx context.Context, wg *sync.WaitGroup, cfg *RemoteOptions) {
	l, err := net.Listen("tcp", cfg.CADDR)
	if err != nil {
		log.Printf("Error listening: %v", err.Error())
		os.Exit(1)
	}
	defer l.Close()

	log.Printf("[i] Listening on %s", cfg.CADDR)

	wg.Done()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[i] Stop listening on %s\n", cfg.CADDR)
			return
		default:
			conn, err := l.Accept()
			if err != nil {
				log.Fatalf("[x] Error accepting: %v", err.Error())
			}

			go handleRequest(conn)
		}
	}
}

func handleRequest(conn net.Conn) {
	buf := make([]byte, 1024)

	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		log.Printf("[!] Possibly vulnerable host identified: %v:%d", addr.IP.String(), addr.Port)
	}

	_, err := conn.Read(buf)
	if err != nil {
		log.Printf("Error reading: %v", err.Error())
	}

	conn.Close()
}

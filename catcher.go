package main

import (
	"log"
	"net"
	"os"
	"sync"
)

func startCatcher(callbackAddr string, wg *sync.WaitGroup) {
	defer wg.Done()

	l, err := net.Listen("tcp", callbackAddr)
	if err != nil {
		log.Printf("Error listening: %v", err.Error())
		os.Exit(1)
	}
	defer l.Close()

	log.Printf("[i] Listening on %s\n---------", callbackAddr)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Error accepting: %v", err.Error())
			os.Exit(1)
		}
		go handleRequest(conn)
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

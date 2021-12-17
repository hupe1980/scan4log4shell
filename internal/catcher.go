package internal

import (
	"context"
	"net"
	"sync"
)

type CallbackHandlerFunc func(addr *net.TCPAddr)

type CallbackCatcher struct {
	handlers []CallbackHandlerFunc
}

func NewCallBackCatcher() *CallbackCatcher {
	return &CallbackCatcher{
		handlers: []CallbackHandlerFunc{},
	}
}

func (cc *CallbackCatcher) Listen(ctx context.Context, network string, address string, wg *sync.WaitGroup) error {
	l, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	defer l.Close()

	wg.Done()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			conn, err := l.Accept()
			if err != nil {
				return err
			}

			go cc.handleRequest(conn)
		}
	}
}

func (cc *CallbackCatcher) Handler(fn CallbackHandlerFunc) {
	cc.handlers = append(cc.handlers, fn)
}

func (cc *CallbackCatcher) handleRequest(conn net.Conn) {
	defer conn.Close()

	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		for _, handler := range cc.handlers {
			handler(addr)
		}
	}

	_, _ = conn.Read(nil)
}

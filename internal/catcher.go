package internal

import (
	"context"
	"net"
)

type CallbackHandlerFunc func(addr *net.TCPAddr)

type CallbackCatcher struct {
	listener net.Listener
	handlers []CallbackHandlerFunc
}

func NewCallBackCatcher(network string, address string) (*CallbackCatcher, error) {
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	return &CallbackCatcher{
		listener: l,
		handlers: []CallbackHandlerFunc{},
	}, nil
}

func (cc *CallbackCatcher) Listen(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			conn, err := cc.listener.Accept()
			if err != nil {
				return err
			}

			go cc.handleRequest(conn)
		}
	}
}

func (cc *CallbackCatcher) Close() error {
	return cc.listener.Close()
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

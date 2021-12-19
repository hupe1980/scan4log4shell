package internal

import (
	"context"
	"fmt"
	"net"
	"time"

	ishc "github.com/projectdiscovery/interactsh/pkg/client"
	ishs "github.com/projectdiscovery/interactsh/pkg/server"
)

type CallbackHandlerFunc func(remoteAddr string)

type CallbackCatcher interface {
	Listen(ctx context.Context) error
	Close() error
	Handler(fn CallbackHandlerFunc)
	Addr() string
}

type tcpCallbackCatcher struct {
	addr     string
	quit     chan interface{}
	listener net.Listener
	handlers []CallbackHandlerFunc
}

func NewTCPCallBackCatcher(network string, address string) (CallbackCatcher, error) {
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	return &tcpCallbackCatcher{
		addr:     address,
		listener: l,
		quit:     make(chan interface{}),
		handlers: []CallbackHandlerFunc{},
	}, nil
}

func (cc *tcpCallbackCatcher) Listen(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			conn, err := cc.listener.Accept()
			if err != nil {
				select {
				case <-cc.quit:
					return nil
				default:
					return err
				}
			}

			go cc.handleRequest(conn)
		}
	}
}

func (cc *tcpCallbackCatcher) Addr() string {
	return cc.addr
}

func (cc *tcpCallbackCatcher) Close() error {
	close(cc.quit)
	return cc.listener.Close()
}

func (cc *tcpCallbackCatcher) Handler(fn CallbackHandlerFunc) {
	cc.handlers = append(cc.handlers, fn)
}

func (cc *tcpCallbackCatcher) handleRequest(conn net.Conn) {
	defer conn.Close()

	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		for _, handler := range cc.handlers {
			handler(fmt.Sprintf("%s:%d", addr.IP.String(), addr.Port))
		}
	}

	_, _ = conn.Read(nil)
}

type interactsh struct {
	client   *ishc.Client
	handlers []CallbackHandlerFunc
}

func NewInteractsh(addr string) (CallbackCatcher, error) {
	opts := &ishc.Options{
		ServerURL: fmt.Sprintf("https://%s", addr),
	}

	client, err := ishc.New(opts)
	if err != nil {
		return nil, err
	}

	return &interactsh{
		client:   client,
		handlers: []CallbackHandlerFunc{},
	}, nil
}

func (cc *interactsh) Addr() string {
	return cc.client.URL()
}

func (cc *interactsh) Listen(ctx context.Context) error {
	cc.client.StartPolling(1*time.Second, func(i *ishs.Interaction) {
		for _, handler := range cc.handlers {
			handler(i.RemoteAddress)
		}
	})

	return nil
}

func (cc *interactsh) Close() error {
	cc.client.StopPolling()
	return nil
}

func (cc *interactsh) Handler(fn CallbackHandlerFunc) {
	cc.handlers = append(cc.handlers, fn)
}

package internal

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"time"

	ishc "github.com/projectdiscovery/interactsh/pkg/client"
	ishs "github.com/projectdiscovery/interactsh/pkg/server"
	ldap "github.com/vjeantet/ldapserver"
)

type CallbackHandlerFunc func(remoteAddr, resource string)

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
			handler(fmt.Sprintf("%s:%d", addr.IP.String(), addr.Port), "")
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
			handler(i.RemoteAddress, "")
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

type ldapCatcher struct {
	server   *ldap.Server
	addr     string
	handlers []CallbackHandlerFunc
}

func NewLDAPCatcher(addr string) (CallbackCatcher, error) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = fmt.Sprintf("%s:%s", addr, "389")
	}

	ldap.Logger = log.New(ioutil.Discard, "", 0)

	server := ldap.NewServer()

	ldapCatchter := &ldapCatcher{
		server:   server,
		addr:     addr,
		handlers: []CallbackHandlerFunc{},
	}

	routes := ldap.NewRouteMux()
	routes.Bind(ldapCatchter.handleBind)
	routes.Search(ldapCatchter.handleSearch)

	ldapCatchter.server.Handle(routes)

	return ldapCatchter, nil
}

func (lc *ldapCatcher) Listen(ctx context.Context) error {
	return lc.server.ListenAndServe(lc.addr)
}

func (lc *ldapCatcher) Addr() string {
	return lc.addr
}

func (lc *ldapCatcher) Close() error {
	lc.server.Stop()
	return nil
}

func (lc *ldapCatcher) Handler(fn CallbackHandlerFunc) {
	lc.handlers = append(lc.handlers, fn)
}

func (lc *ldapCatcher) handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func (lc *ldapCatcher) handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	req := m.GetSearchRequest()

	for _, handler := range lc.handlers {
		handler(m.Client.Addr().String(), string(req.BaseObject()))
	}

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

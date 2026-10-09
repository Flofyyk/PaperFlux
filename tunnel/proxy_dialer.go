package tunnel

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// ProxyDialer resolves domain requests using DNS-over-TCP over the real data
// path. Physical-network DNS is used only for bootstrapping document providers.
type ProxyDialer struct {
	parent context.Context
	dial   func(string) (net.Conn, error)
	probe  func(context.Context, string) (net.Conn, error)
}

func NewProxyDialer(t *TCPTunnel) *ProxyDialer {
	return &ProxyDialer{parent: t.lifecycleContext, dial: t.DialTCP, probe: t.DialProbe}
}

func (p *ProxyDialer) DialTCP(address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return nil, fmt.Errorf("proxy supports IPv4 destinations only")
		}
		return p.dial(address)
	}
	ctx, cancel := context.WithTimeout(p.parent, 8*time.Second)
	defer cancel()
	var last error
	for _, server := range []string{"77.88.8.8:53", "77.88.8.1:53"} {
		conn, e := p.probe(ctx, server)
		if e != nil {
			last = e
			continue
		}
		deadline, _ := ctx.Deadline()
		_ = conn.SetDeadline(deadline)
		dc := &dns.Conn{Conn: conn}
		q := new(dns.Msg).SetQuestion(dns.Fqdn(host), dns.TypeA)
		e = dc.WriteMsg(q)
		var answer *dns.Msg
		if e == nil {
			answer, e = dc.ReadMsg()
		}
		_ = conn.Close()
		if e != nil {
			last = e
			continue
		}
		if answer.Id != q.Id || !answer.Response || answer.Rcode != dns.RcodeSuccess {
			last = fmt.Errorf("invalid proxy DNS response")
			continue
		}
		for _, record := range answer.Answer {
			if a, ok := record.(*dns.A); ok {
				return p.dial(net.JoinHostPort(a.A.String(), port))
			}
		}
		last = fmt.Errorf("proxy DNS returned no IPv4 address")
	}
	return nil, fmt.Errorf("tunneled DNS failed: %w", last)
}

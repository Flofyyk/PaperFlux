package tunnel

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"testing"
)

func TestProxyDomainsUseTunneledDNS(t *testing.T) {
	calls := 0
	dialed := ""
	p := &ProxyDialer{parent: context.Background(),
		dial: func(addr string) (net.Conn, error) { dialed = addr; return nil, nil },
		probe: func(ctx context.Context, addr string) (net.Conn, error) {
			calls++
			if addr != "77.88.8.8:53" {
				t.Errorf("unexpected probe: %s", addr)
			}
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				dc := &dns.Conn{Conn: server}
				question, err := dc.ReadMsg()
				if err != nil {
					return
				}
				answer := new(dns.Msg).SetReply(question)
				answer.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IPv4(192, 0, 2, 7)}}
				_ = dc.WriteMsg(answer)
			}()
			return client, nil
		},
	}
	if _, err := p.DialTCP("example.test:443"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || dialed != "192.0.2.7:443" {
		t.Fatalf("calls=%d target=%s", calls, dialed)
	}
}

func TestProxyDNSFailureDoesNotUseDirectFallback(t *testing.T) {
	calls := 0
	p := &ProxyDialer{parent: context.Background(),
		dial:  func(addr string) (net.Conn, error) { t.Fatal("unexpected target dial"); return nil, nil },
		probe: func(context.Context, string) (net.Conn, error) { calls++; return nil, fmt.Errorf("carrier down") },
	}
	if _, err := p.DialTCP("example.invalid:443"); err == nil {
		t.Fatal("DNS failure was hidden")
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestProxyIPAddressSkipsDNSAndRejectsIPv6(t *testing.T) {
	calls := 0
	p := &ProxyDialer{parent: context.Background(),
		dial:  func(addr string) (net.Conn, error) { calls++; return nil, nil },
		probe: func(context.Context, string) (net.Conn, error) { t.Fatal("unexpected DNS probe"); return nil, nil },
	}
	if _, err := p.DialTCP("192.0.2.1:443"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.DialTCP("[2001:db8::1]:443"); err == nil {
		t.Fatal("IPv6 accepted")
	}
	if calls != 1 {
		t.Fatal(calls)
	}
}

package tunnel

import (
	"context"
	"github.com/miekg/dns"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProbeBackupHasIndependentBudget(t *testing.T) {
	calls := 0
	dial := func(ctx context.Context, target string) (net.Conn, error) {
		calls++
		if calls == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if ctx.Err() != nil {
			t.Fatal("backup inherited expired context")
		}
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			dc := &dns.Conn{Conn: b}
			q, err := dc.ReadMsg()
			if err != nil {
				return
			}
			reply := new(dns.Msg).SetReply(q)
			rr, _ := dns.NewRR("yandex.ru. 10 IN A 1.2.3.4")
			reply.Answer = []dns.RR{rr}
			_ = dc.WriteMsg(reply)
		}()
		return a, nil
	}
	if err := probeDNS(context.Background(), dial, []string{"first:53", "backup:53"}, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestProbeCancellationStopsReadAndFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	dial := func(context.Context, string) (net.Conn, error) {
		calls++
		a, b := net.Pipe()
		t.Cleanup(func() { b.Close() })
		cancel()
		return a, nil
	}
	started := time.Now()
	if err := probeDNS(ctx, dial, []string{"a", "b"}, time.Hour); err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 || time.Since(started) > time.Second {
		t.Fatal("cancellation not propagated")
	}
}

func TestProbeUsesConfiguredResolvers(t *testing.T) {
	t.Setenv("PAPERFLUX_DNS_PRIMARY", "1.1.1.1")
	t.Setenv("PAPERFLUX_DNS_SECONDARY", "8.8.8.8")
	if got := strings.Join(probeResolvers(), ","); got != "1.1.1.1:53,8.8.8.8:53" {
		t.Fatal(got)
	}
	t.Setenv("PAPERFLUX_DNS_SECONDARY", "1.1.1.1")
	if len(probeResolvers()) != 1 {
		t.Fatal("duplicate resolver")
	}
}

func TestProbeReportsEachFailureWithoutPrivateError(t *testing.T) {
	dial := func(ctx context.Context, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	err := probeDNS(context.Background(), dial, []string{"1.1.1.1:53", "8.8.8.8:53"}, time.Millisecond)
	if err == nil || strings.Count(err.Error(), "reason=timeout") != 2 {
		t.Fatalf("error=%v", err)
	}
}

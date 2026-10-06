package exitgroup

import (
	"testing"
	"time"
)

func TestExpandedPoolAndRuntimeGroupLimit(t *testing.T) {
	for _, ip := range []string{"10.10.10.2", "10.10.10.254", "10.10.11.2", "10.10.26.49", "10.10.26.50", "10.10.89.14"} {
		p := profile("1")
		p.ClientIP = ip
		if err := manifest(p).Validate(time.Now()); err != nil {
			t.Fatalf("pool address rejected: %s: %v", ip, err)
		}
	}
	for _, ip := range []string{"10.10.10.0", "10.10.11.1", "10.10.11.255", "10.10.89.15", "10.10.90.2", "10.11.11.2", "::ffff:10.10.11.2"} {
		p := profile("1")
		p.ClientIP = ip
		if err := manifest(p).Validate(time.Now()); err == nil {
			t.Fatalf("out-of-pool address accepted: %s", ip)
		}
	}
	if MaxProfiles != 64 {
		t.Fatal("unexpected bounded runtime group limit")
	}
}

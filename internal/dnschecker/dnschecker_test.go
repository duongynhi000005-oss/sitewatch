package dnschecker

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Ricky1800/sitewatch/internal/clock"
	"github.com/Ricky1800/sitewatch/internal/config"
)

// FakeResolver implements Resolver using function fields for unit testing.
type FakeResolver struct {
	LookupIPFunc    func(ctx context.Context, network, host string) ([]net.IP, error)
	LookupCNAMEFunc func(ctx context.Context, host string) (string, error)
}

func (f *FakeResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if f.LookupIPFunc != nil {
		return f.LookupIPFunc(ctx, network, host)
	}
	return nil, nil
}

func (f *FakeResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	if f.LookupCNAMEFunc != nil {
		return f.LookupCNAMEFunc(ctx, host)
	}
	return "", nil
}

func TestChecker_SuccessA(t *testing.T) {
	fake := &FakeResolver{
		LookupIPFunc: func(ctx context.Context, network, host string) ([]net.IP, error) {
			if network != "ip4" {
				t.Errorf("expected network ip4, got %s", network)
			}
			if host != "example.com" {
				t.Errorf("expected host example.com, got %s", host)
			}
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		},
	}

	c := &Checker{Resolver: fake, Clock: clock.NewFake(time.Unix(0, 0))}
	chk := config.Check{
		Name:       "Example DNS",
		Type:       "dns",
		Host:       "example.com",
		RecordType: "A",
		Timeout:    config.Duration(2 * time.Second),
	}

	res := c.Check(context.Background(), chk)
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	if res.Name != "Example DNS" {
		t.Errorf("expected name 'Example DNS', got %q", res.Name)
	}
	if res.URL != "example.com" {
		t.Errorf("expected URL 'example.com', got %q", res.URL)
	}
}

func TestChecker_SuccessExpectedIP(t *testing.T) {
	fake := &FakeResolver{
		LookupIPFunc: func(ctx context.Context, network, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}, nil
		},
	}

	c := &Checker{Resolver: fake}
	chk := config.Check{
		Name:       "Example DNS",
		Type:       "dns",
		Host:       "example.com",
		RecordType: "A",
		ExpectedIP: "192.0.2.2",
		Timeout:    config.Duration(2 * time.Second),
	}

	res := c.Check(context.Background(), chk)
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
}

func TestChecker_MismatchedExpectedIP(t *testing.T) {
	fake := &FakeResolver{
		LookupIPFunc: func(ctx context.Context, network, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		},
	}

	c := &Checker{Resolver: fake}
	chk := config.Check{
		Name:       "Example DNS",
		Type:       "dns",
		Host:       "example.com",
		RecordType: "A",
		ExpectedIP: "192.0.2.99",
		Timeout:    config.Duration(2 * time.Second),
	}

	res := c.Check(context.Background(), chk)
	if res.Success {
		t.Fatal("expected failure when expected IP is missing")
	}
}

func TestChecker_SuccessAAAA(t *testing.T) {
	fake := &FakeResolver{
		LookupIPFunc: func(ctx context.Context, network, host string) ([]net.IP, error) {
			if network != "ip6" {
				t.Errorf("expected network ip6, got %s", network)
			}
			return []net.IP{net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")}, nil
		},
	}

	c := &Checker{Resolver: fake}
	chk := config.Check{
		Name:       "Example IPv6",
		Type:       "dns",
		Host:       "example.com",
		RecordType: "AAAA",
		ExpectedIP: "2606:2800:220:1:248:1893:25c8:1946",
		Timeout:    config.Duration(2 * time.Second),
	}

	res := c.Check(context.Background(), chk)
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
}

func TestChecker_SuccessCNAME(t *testing.T) {
	fake := &FakeResolver{
		LookupCNAMEFunc: func(ctx context.Context, host string) (string, error) {
			return "target.example.org.", nil
		},
	}

	c := &Checker{Resolver: fake}
	chk := config.Check{
		Name:       "Example CNAME",
		Type:       "dns",
		Host:       "alias.example.com",
		RecordType: "CNAME",
		ExpectedIP: "target.example.org",
		Timeout:    config.Duration(2 * time.Second),
	}

	res := c.Check(context.Background(), chk)
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
}

func TestChecker_MismatchedCNAME(t *testing.T) {
	fake := &FakeResolver{
		LookupCNAMEFunc: func(ctx context.Context, host string) (string, error) {
			return "other.example.org.", nil
		},
	}

	c := &Checker{Resolver: fake}
	chk := config.Check{
		Name:       "Example CNAME",
		Type:       "dns",
		Host:       "alias.example.com",
		RecordType: "CNAME",
		ExpectedIP: "target.example.org",
		Timeout:    config.Duration(2 * time.Second),
	}

	res := c.Check(context.Background(), chk)
	if res.Success {
		t.Fatal("expected failure on mismatched CNAME")
	}
}

func TestChecker_LookupError(t *testing.T) {
	fake := &FakeResolver{
		LookupIPFunc: func(ctx context.Context, network, host string) ([]net.IP, error) {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		},
	}

	c := &Checker{Resolver: fake}
	chk := config.Check{
		Name:       "Nonexistent",
		Type:       "dns",
		Host:       "nonexistent.example.invalid",
		RecordType: "A",
		Timeout:    config.Duration(2 * time.Second),
	}

	res := c.Check(context.Background(), chk)
	if res.Success {
		t.Fatal("expected failure on lookup error")
	}
	if res.Error == "" {
		t.Fatal("expected non-empty error")
	}
}

func TestChecker_EmptyIPs(t *testing.T) {
	fake := &FakeResolver{
		LookupIPFunc: func(ctx context.Context, network, host string) ([]net.IP, error) {
			return []net.IP{}, nil
		},
	}

	c := &Checker{Resolver: fake}
	chk := config.Check{
		Name:       "Empty",
		Type:       "dns",
		Host:       "empty.example.com",
		RecordType: "A",
		Timeout:    config.Duration(2 * time.Second),
	}

	res := c.Check(context.Background(), chk)
	if res.Success {
		t.Fatal("expected failure on empty IPs")
	}
}

func TestEvaluate_MaxResponseMS(t *testing.T) {
	chk := config.Check{
		Name:          "Slow",
		Type:          "dns",
		Host:          "example.com",
		RecordType:    "A",
		MaxResponseMS: 50,
	}

	res := Evaluate(chk, time.Now(), Metrics{
		ResponseTime: 100 * time.Millisecond,
		IPs:          []net.IP{net.ParseIP("93.184.216.34")},
	})

	if res.Success {
		t.Fatal("expected failure when response time exceeds max_response_ms")
	}
}

func TestEvaluate_MetricsError(t *testing.T) {
	chk := config.Check{
		Name: "Err",
		Host: "example.com",
	}

	res := Evaluate(chk, time.Now(), Metrics{
		Err: errors.New("timeout"),
	})

	if res.Success {
		t.Fatal("expected failure on metrics error")
	}
	if res.Error != "timeout" {
		t.Errorf("expected 'timeout', got %q", res.Error)
	}
}

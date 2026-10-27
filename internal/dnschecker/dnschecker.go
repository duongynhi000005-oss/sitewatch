// Package dnschecker performs DNS resolution checks (A, AAAA, CNAME)
// against a configured domain and evaluates the result against expectations.
package dnschecker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Ricky1800/sitewatch/internal/checker"
	"github.com/Ricky1800/sitewatch/internal/clock"
	"github.com/Ricky1800/sitewatch/internal/config"
)

// Resolver abstracts net.Resolver so unit tests can inject fake lookups
// without hitting real DNS servers.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// Metrics is the raw, unevaluated outcome of performing a DNS lookup. It is
// intentionally separate from checker.Result so that the pass/fail evaluation
// logic (Evaluate) can be unit tested with fabricated metrics and no real
// network call.
type Metrics struct {
	ResponseTime time.Duration
	IPs          []net.IP
	CNAME        string
	Err          error
}

// Checker performs DNS checks. The zero value is usable; Resolver and Clock
// default to net.DefaultResolver and clock.Real when nil.
type Checker struct {
	Resolver Resolver
	Clock    clock.Clock
}

func (c *Checker) resolver() Resolver {
	if c.Resolver != nil {
		return c.Resolver
	}
	return net.DefaultResolver
}

func (c *Checker) clockOrReal() clock.Clock {
	if c.Clock != nil {
		return c.Clock
	}
	return clock.Real{}
}

// Check performs the DNS lookup for chk and evaluates it.
func (c *Checker) Check(ctx context.Context, chk config.Check) checker.Result {
	m := c.do(ctx, chk)
	return Evaluate(chk, c.clockOrReal().Now(), m)
}

// do performs the actual DNS lookup and collects raw metrics. It does not
// interpret pass/fail; see Evaluate for that.
func (c *Checker) do(ctx context.Context, chk config.Check) Metrics {
	ctx, cancel := context.WithTimeout(ctx, chk.Timeout.Std())
	defer cancel()

	host := chk.Host
	recType := strings.ToUpper(chk.RecordType)
	if recType == "" {
		recType = "A"
	}

	start := time.Now()
	var (
		ips   []net.IP
		cname string
		err   error
	)

	switch recType {
	case "CNAME":
		cname, err = c.resolver().LookupCNAME(ctx, host)
	case "AAAA":
		ips, err = c.resolver().LookupIP(ctx, "ip6", host)
	case "A":
		ips, err = c.resolver().LookupIP(ctx, "ip4", host)
	default:
		ips, err = c.resolver().LookupIP(ctx, "ip", host)
	}

	elapsed := time.Since(start)
	return Metrics{
		ResponseTime: elapsed,
		IPs:          ips,
		CNAME:        cname,
		Err:          err,
	}
}

// Evaluate applies chk's expectations to m and produces a checker.Result.
func Evaluate(chk config.Check, now time.Time, m Metrics) checker.Result {
	res := checker.Result{
		Name:         chk.Name,
		URL:          chk.Host,
		Time:         now,
		ResponseTime: m.ResponseTime,
	}

	if m.Err != nil {
		res.Success = false
		res.Error = m.Err.Error()
		return res
	}

	recType := strings.ToUpper(chk.RecordType)
	if recType == "" {
		recType = "A"
	}

	if recType == "CNAME" {
		if m.CNAME == "" {
			res.Success = false
			res.Error = "no CNAME record found"
			return res
		}
		if chk.ExpectedIP != "" {
			got := strings.TrimSuffix(m.CNAME, ".")
			expected := strings.TrimSuffix(chk.ExpectedIP, ".")
			if !strings.EqualFold(got, expected) {
				res.Success = false
				res.Error = fmt.Sprintf("expected CNAME %q, got %q", chk.ExpectedIP, m.CNAME)
				return res
			}
		}
	} else {
		if len(m.IPs) == 0 {
			res.Success = false
			res.Error = "no IP addresses found"
			return res
		}
		if chk.ExpectedIP != "" {
			expectedIP := net.ParseIP(chk.ExpectedIP)
			found := false
			for _, ip := range m.IPs {
				if ip.Equal(expectedIP) {
					found = true
					break
				}
			}
			if !found {
				res.Success = false
				res.Error = fmt.Sprintf("expected IP %s not found in resolved IPs %v", chk.ExpectedIP, m.IPs)
				return res
			}
		}
	}

	if chk.MaxResponseMS > 0 && m.ResponseTime > time.Duration(chk.MaxResponseMS)*time.Millisecond {
		res.Success = false
		res.Error = "response time exceeded max_response_ms"
		return res
	}

	res.Success = true
	return res
}

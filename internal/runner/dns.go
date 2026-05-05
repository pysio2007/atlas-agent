package runner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

type DNSRunner struct{}

func (d *DNSRunner) Run(ctx context.Context, target string, options any) (any, error) {
	qname := target
	qtype := "A"
	resolver := "172.20.0.53"

	if m, ok := options.(map[string]any); ok {
		if v, ok := m["qname"]; ok {
			if s, ok := v.(string); ok {
				qname = s
			}
		}
		if v, ok := m["qtype"]; ok {
			if s, ok := v.(string); ok {
				qtype = s
			}
		}
		if v, ok := m["resolver"]; ok {
			if s, ok := v.(string); ok {
				resolver = s
			}
		}
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(resolver, "53"))
		},
	}

	start := time.Now()
	answers := []map[string]any{}
	var rcode string
	elapsed := time.Since(start).Seconds() * 1000

	switch strings.ToUpper(qtype) {
	case "A":
		addrs, err := r.LookupHost(ctx, qname)
		elapsed = time.Since(start).Seconds() * 1000
		if err != nil {
			rcode = "NXDOMAIN"
			return dnsResult(qname, qtype, resolver, "NXDOMAIN", answers, elapsed), nil
		}
		rcode = "NOERROR"
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				answers = append(answers, map[string]any{
					"name":  qname,
					"type":  "A",
					"ttl":   300,
					"rdata": a,
				})
			}
		}

	case "AAAA":
		addrs, err := r.LookupHost(ctx, qname)
		elapsed = time.Since(start).Seconds() * 1000
		if err != nil {
			return dnsResult(qname, qtype, resolver, "NXDOMAIN", answers, elapsed), nil
		}
		rcode = "NOERROR"
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() == nil {
				answers = append(answers, map[string]any{
					"name":  qname,
					"type":  "AAAA",
					"ttl":   300,
					"rdata": a,
				})
			}
		}

	case "MX":
		mx, err := r.LookupMX(ctx, qname)
		elapsed = time.Since(start).Seconds() * 1000
		if err != nil {
			return dnsResult(qname, qtype, resolver, "NXDOMAIN", answers, elapsed), nil
		}
		rcode = "NOERROR"
		for _, r := range mx {
			answers = append(answers, map[string]any{
				"name":  qname,
				"type":  "MX",
				"ttl":   300,
				"rdata": fmt.Sprintf("%d %s", r.Pref, r.Host),
			})
		}

	case "TXT":
		txts, err := r.LookupTXT(ctx, qname)
		elapsed = time.Since(start).Seconds() * 1000
		if err != nil {
			return dnsResult(qname, qtype, resolver, "NXDOMAIN", answers, elapsed), nil
		}
		rcode = "NOERROR"
		for _, t := range txts {
			answers = append(answers, map[string]any{
				"name":  qname,
				"type":  "TXT",
				"ttl":   300,
				"rdata": t,
			})
		}

	default:
		addrs, err := r.LookupHost(ctx, qname)
		elapsed = time.Since(start).Seconds() * 1000
		if err != nil {
			return dnsResult(qname, qtype, resolver, "NXDOMAIN", answers, elapsed), nil
		}
		rcode = "NOERROR"
		for _, a := range addrs {
			answers = append(answers, map[string]any{
				"name":  qname,
				"type":  qtype,
				"ttl":   300,
				"rdata": a,
			})
		}
	}

	elapsed = time.Since(start).Seconds() * 1000
	return dnsResult(qname, qtype, resolver, rcode, answers, elapsed), nil
}

func dnsResult(qname, qtype, resolver, rcode string, answers []map[string]any, latencyMs float64) map[string]any {
	return map[string]any{
		"qname":      qname,
		"qtype":      qtype,
		"resolver":   resolver,
		"answers":    answers,
		"rcode":      rcode,
		"latency_ms": latencyMs,
	}
}

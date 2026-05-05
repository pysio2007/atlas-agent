package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type DNSRunner struct{}

func (d *DNSRunner) Run(ctx context.Context, target string, options any) (any, error) {
	qname := target
	qtype := "A"
	resolver := "172.20.0.53:53"
	timeoutMs := 5000

	if m, ok := options.(map[string]any); ok {
		if v, ok := m["qname"].(string); ok && v != "" {
			qname = v
		}
		if v, ok := m["qtype"].(string); ok && v != "" {
			qtype = strings.ToUpper(v)
		}
		if v, ok := m["resolver"].(string); ok && v != "" {
			resolver = normalizeResolver(v)
		}
		if v, ok := m["timeout_ms"]; ok {
			if n, err := ToInt(v); err == nil {
				timeoutMs = n
			}
		}
	}
	if strings.TrimSpace(qname) == "" {
		return nil, fmt.Errorf("qname is required")
	}
	if timeoutMs < 500 || timeoutMs > 30000 {
		return nil, fmt.Errorf("invalid dns timeout_ms %d: must be 500-30000", timeoutMs)
	}

	qt, ok := dns.StringToType[strings.ToUpper(qtype)]
	if !ok {
		return nil, fmt.Errorf("unsupported dns qtype: %s", qtype)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), qt)
	client := &dns.Client{Net: "udp", Timeout: time.Duration(timeoutMs) * time.Millisecond}

	start := time.Now()
	reply, _, err := client.ExchangeContext(ctx, msg, resolver)
	latencyMs := float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		errorType := dnsErrorType(err)
		return dnsResult(qname, qtype, resolver, "", nil, latencyMs, errorType, err.Error()), nil
	}

	answers := make([]map[string]any, 0, len(reply.Answer))
	for _, rr := range reply.Answer {
		header := rr.Header()
		answers = append(answers, map[string]any{
			"name":  header.Name,
			"type":  dns.TypeToString[header.Rrtype],
			"ttl":   header.Ttl,
			"rdata": strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(rr.String(), header.String())), "\t"),
		})
	}

	rcode := dns.RcodeToString[reply.Rcode]
	errorType := ""
	status := "ok"
	if reply.Rcode != dns.RcodeSuccess {
		status = "error"
		if reply.Rcode == dns.RcodeNameError {
			errorType = "nxdomain"
		} else {
			errorType = "dns_rcode"
		}
	}
	result := dnsResult(qname, qtype, resolver, rcode, answers, latencyMs, errorType, "")
	result["measurement_status"] = status
	return result, nil
}

func normalizeResolver(resolver string) string {
	if _, _, err := net.SplitHostPort(resolver); err == nil {
		return resolver
	}
	return net.JoinHostPort(resolver, "53")
}

func dnsErrorType(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "error"
}

func dnsResult(qname, qtype, resolver, rcode string, answers []map[string]any, latencyMs float64, errorType, errMsg string) map[string]any {
	if answers == nil {
		answers = []map[string]any{}
	}
	result := map[string]any{
		"qname":              qname,
		"qtype":              qtype,
		"resolver":           resolver,
		"answers":            answers,
		"rcode":              rcode,
		"latency_ms":         latencyMs,
		"error_type":         errorType,
		"measurement_status": "ok",
	}
	if errMsg != "" {
		result["error"] = errMsg
		result["measurement_status"] = "error"
	}
	return result
}

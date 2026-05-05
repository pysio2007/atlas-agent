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
	proto := "udp"

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
		if v, ok := m["proto"].(string); ok && v != "" {
			proto = strings.ToLower(v)
		}
	}
	if strings.TrimSpace(qname) == "" {
		return nil, fmt.Errorf("qname is required")
	}
	if timeoutMs < 500 || timeoutMs > 30000 {
		return nil, fmt.Errorf("invalid dns timeout_ms %d: must be 500-30000", timeoutMs)
	}
	if proto != "udp" && proto != "tcp" {
		return nil, fmt.Errorf("invalid dns proto %s: must be udp or tcp", proto)
	}

	qt, ok := dns.StringToType[strings.ToUpper(qtype)]
	if !ok {
		return nil, fmt.Errorf("unsupported dns qtype: %s", qtype)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), qt)
	client := &dns.Client{Net: proto, Timeout: time.Duration(timeoutMs) * time.Millisecond}

	start := time.Now()
	reply, _, err := client.ExchangeContext(ctx, msg, resolver)
	if err == nil && reply != nil && reply.Truncated && proto == "udp" {
		client.Net = "tcp"
		proto = "tcp"
		reply, _, err = client.ExchangeContext(ctx, msg, resolver)
	}
	latencyMs := float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		errorType := dnsErrorType(err)
		return dnsResult(qname, qtype, resolver, proto, "", 0, nil, nil, nil, nil, latencyMs, errorType, err.Error()), nil
	}
	if reply == nil {
		return dnsResult(qname, qtype, resolver, proto, "", 0, nil, nil, nil, nil, latencyMs, "error", "empty dns reply"), nil
	}

	questions := make([]map[string]any, 0, len(reply.Question))
	for _, q := range reply.Question {
		questions = append(questions, map[string]any{
			"name":  q.Name,
			"type":  dns.TypeToString[q.Qtype],
			"class": dns.ClassToString[q.Qclass],
		})
	}
	answers := dnsSection(reply.Answer)
	authority := dnsSection(reply.Ns)
	additional := dnsSection(reply.Extra)

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
	flags := map[string]any{
		"authoritative":       reply.Authoritative,
		"truncated":           reply.Truncated,
		"recursion_desired":   reply.RecursionDesired,
		"recursion_available": reply.RecursionAvailable,
		"authenticated_data":  reply.AuthenticatedData,
		"checking_disabled":   reply.CheckingDisabled,
	}
	result := dnsResult(qname, qtype, resolver, proto, rcode, reply.Rcode, questions, answers, authority, additional, latencyMs, errorType, "")
	result["flags"] = flags
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

func dnsSection(records []dns.RR) []map[string]any {
	items := make([]map[string]any, 0, len(records))
	for _, rr := range records {
		header := rr.Header()
		items = append(items, map[string]any{
			"name":  header.Name,
			"type":  dns.TypeToString[header.Rrtype],
			"ttl":   header.Ttl,
			"class": dns.ClassToString[header.Class],
			"rdata": strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(rr.String(), header.String())), "\t"),
		})
	}
	return items
}

func dnsResult(qname, qtype, resolver, proto, rcode string, rcodeValue int, questions, answers, authority, additional []map[string]any, latencyMs float64, errorType, errMsg string) map[string]any {
	if questions == nil {
		questions = []map[string]any{}
	}
	if answers == nil {
		answers = []map[string]any{}
	}
	if authority == nil {
		authority = []map[string]any{}
	}
	if additional == nil {
		additional = []map[string]any{}
	}
	result := map[string]any{
		"qname":              qname,
		"qtype":              qtype,
		"resolver":           resolver,
		"protocol":           proto,
		"questions":          questions,
		"answers":            answers,
		"authority":          authority,
		"additional":         additional,
		"rcode":              rcode,
		"rcode_value":        rcodeValue,
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

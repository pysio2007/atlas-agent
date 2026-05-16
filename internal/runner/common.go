package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type CapabilityReport struct {
	Capabilities []string
	Versions     map[string]string
}

func DetectCapabilities(ctx context.Context) CapabilityReport {
	report := CapabilityReport{
		Capabilities: []string{"dns", "http", "tls", "ntp"},
		Versions:     map[string]string{},
	}

	if version, ok := detectCommandVersion(ctx, "ping", []string{"-V"}); ok {
		report.Capabilities = append(report.Capabilities, "ping")
		report.Versions["ping"] = version
	}

	if version, ok := detectCommandVersion(ctx, "traceroute", []string{"--version"}, []string{"-V"}); ok {
		report.Capabilities = append(report.Capabilities, "traceroute")
		report.Versions["traceroute"] = version
	}
	report.Capabilities = append(report.Capabilities, "sslcert")
	report.Versions["sslcert"] = "tls-runner"

	return report
}

func detectCommandVersion(ctx context.Context, name string, argSets ...[]string) (string, bool) {
	if _, err := exec.LookPath(name); err != nil {
		return "", false
	}
	for _, args := range argSets {
		versionCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		cmd := exec.CommandContext(versionCtx, name, args...)
		out, err := cmd.CombinedOutput()
		cancel()
		if len(out) == 0 && err != nil {
			continue
		}
		version := firstNonEmptyLine(string(out))
		if version == "" {
			version = strings.TrimSpace(string(out))
		}
		if version != "" {
			return version, true
		}
	}
	return "", false
}

func firstNonEmptyLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func splitHostPortDefault(target, defaultPort string) (string, string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", "", fmt.Errorf("target is required")
	}
	if strings.HasPrefix(target, "-") {
		return "", "", fmt.Errorf("invalid target: must not start with '-'")
	}
	if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		return strings.TrimPrefix(strings.TrimSuffix(target, "]"), "["), defaultPort, nil
	}
	if host, port, err := net.SplitHostPort(target); err == nil {
		return host, port, nil
	}
	return target, defaultPort, nil
}

func measurementErrorResult(target, host, port string, timeoutMs int, timings map[string]float64, err error) map[string]any {
	result := map[string]any{
		"target":             target,
		"host":               host,
		"port":               port,
		"timeout_ms":         timeoutMs,
		"measurement_status": "error",
		"error_type":         errorType(err),
		"error":              err.Error(),
	}
	if timings != nil {
		result["timings"] = timings
	}
	return result
}

func errorType(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(err.Error()), "timeout") {
		return "timeout"
	}
	return "error"
}

func lookupIPAddrWithDN42Fallback(ctx context.Context, host string) ([]net.IPAddr, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err == nil && len(addrs) > 0 {
		return addrs, nil
	}
	if !isDN42DNSName(host) {
		return addrs, err
	}
	fallback, fallbackErr := lookupDN42DNS(ctx, host)
	if fallbackErr == nil && len(fallback) > 0 {
		return fallback, nil
	}
	if err != nil {
		return nil, err
	}
	return fallback, fallbackErr
}

func resolveCommandTarget(ctx context.Context, target string) string {
	if !isDN42DNSName(target) {
		return target
	}
	addrs, err := lookupIPAddrWithDN42Fallback(ctx, target)
	if err != nil || len(addrs) == 0 {
		return target
	}
	return addrs[0].IP.String()
}

func isDN42DNSName(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]")), ".")
	return host == "dn42" || strings.HasSuffix(host, ".dn42") || strings.HasSuffix(host, ".internal")
}

func lookupDN42DNS(ctx context.Context, host string) ([]net.IPAddr, error) {
	resolvers := []string{"172.20.0.53:53", "[fd42:d42:d42:53::1]:53"}
	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}
	var out []net.IPAddr
	var lastErr error
	for _, resolver := range resolvers {
		for _, qtype := range qtypes {
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(host), qtype)
			client := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
			reply, _, err := client.ExchangeContext(ctx, msg, resolver)
			if err != nil {
				lastErr = err
				continue
			}
			if reply == nil || reply.Rcode != dns.RcodeSuccess {
				continue
			}
			for _, rr := range reply.Answer {
				switch record := rr.(type) {
				case *dns.A:
					out = append(out, net.IPAddr{IP: record.A})
				case *dns.AAAA:
					out = append(out, net.IPAddr{IP: record.AAAA})
				}
			}
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no dn42 dns records found for %s", host)
}

package runner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"
)

type TLSRunner struct{}

func (t *TLSRunner) Run(ctx context.Context, target string, options any) (any, error) {
	timeoutMs := 10000
	if m, ok := options.(map[string]any); ok {
		if v, ok := m["timeout_ms"]; ok {
			if n, err := ToInt(v); err == nil {
				timeoutMs = n
			}
		}
	}
	if timeoutMs < 500 || timeoutMs > 30000 {
		return nil, fmt.Errorf("invalid tls timeout_ms %d: must be 500-30000", timeoutMs)
	}

	host, port, err := splitHostPortDefault(target, "443")
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	result := map[string]any{
		"target":     target,
		"host":       host,
		"port":       port,
		"timeout_ms": timeoutMs,
	}
	timings := map[string]float64{}
	result["timings"] = timings

	resolvedHost := host
	serverName := host
	if ip := net.ParseIP(host); ip != nil {
		timings["dns_ms"] = 0
		serverName = ""
	} else {
		dnsStart := time.Now()
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return measurementErrorResult(target, host, port, timeoutMs, timings, err), nil
		}
		timings["dns_ms"] = millisSince(dnsStart)
		if len(addrs) == 0 {
			return measurementErrorResult(target, host, port, timeoutMs, timings, fmt.Errorf("no ip addresses found for %s", host)), nil
		}
		resolvedHost = addrs[0].IP.String()
	}

	connectStart := time.Now()
	dialer := net.Dialer{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(resolvedHost, port))
	if err != nil {
		return measurementErrorResult(target, host, port, timeoutMs, timings, err), nil
	}
	timings["connect_ms"] = millisSince(connectStart)
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName})
	if err := tlsConn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)); err != nil {
		return measurementErrorResult(target, host, port, timeoutMs, timings, err), nil
	}
	tlsStart := time.Now()
	if err := tlsConn.Handshake(); err != nil {
		return measurementErrorResult(target, host, port, timeoutMs, timings, err), nil
	}
	timings["tls_ms"] = millisSince(tlsStart)

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return measurementErrorResult(target, host, port, timeoutMs, timings, fmt.Errorf("no peer certificate presented")), nil
	}
	leaf := state.PeerCertificates[0]
	if leaf == nil {
		return measurementErrorResult(target, host, port, timeoutMs, timings, fmt.Errorf("no peer certificate presented")), nil
	}

	result["handshake_ms"] = timings["tls_ms"]
	result["version"] = tlsVersionName(state.Version)
	result["cipher_suite"] = tls.CipherSuiteName(state.CipherSuite)
	result["not_before"] = leaf.NotBefore.UTC().Format(time.RFC3339)
	result["not_after"] = leaf.NotAfter.UTC().Format(time.RFC3339)
	result["subject"] = leaf.Subject.String()
	result["issuer"] = leaf.Issuer.String()
	result["measurement_status"] = "ok"

	return result, nil
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return "0x" + strconv.FormatUint(uint64(version), 16)
	}
}

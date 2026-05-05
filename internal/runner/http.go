package runner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"
)

type HTTPRunner struct{}

func (h *HTTPRunner) Run(ctx context.Context, target string, options any) (any, error) {
	method := "GET"
	timeoutMs := 10000
	followRedirects := true

	if m, ok := options.(map[string]any); ok {
		if v, ok := m["method"]; ok {
			if s, ok := v.(string); ok {
				method = s
			}
		}
		if v, ok := m["timeout_ms"]; ok {
			if n, err := ToInt(v); err == nil {
				timeoutMs = n
			}
		}
		if v, ok := m["follow_redirects"]; ok {
			if b, ok := v.(bool); ok {
				followRedirects = b
			}
		}
	}
	if timeoutMs < 500 || timeoutMs > 30000 {
		return nil, fmt.Errorf("invalid http timeout_ms %d: must be 500-30000", timeoutMs)
	}
	parsedURL, err := url.Parse(target)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Hostname() == "" {
		return nil, fmt.Errorf("invalid http target: scheme must be http or https")
	}
	if ip := net.ParseIP(parsedURL.Hostname()); ip != nil && isBlockedHTTPIP(ip) {
		return nil, fmt.Errorf("http target resolves to a blocked address")
	}

	var bodyBytes int64
	timings := map[string]float64{}
	var dnsStart, connectStart, tlsStart, requestStart time.Time
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		DialContext: (&safeDialer{
			dialer: net.Dialer{Timeout: time.Duration(timeoutMs) * time.Millisecond},
		}).DialContext,
	}
	client := &http.Client{
		Timeout:   time.Duration(timeoutMs) * time.Millisecond,
		Transport: transport,
	}

	if !followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return nil, err
	}
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			if !dnsStart.IsZero() {
				timings["dns_ms"] = millisSince(dnsStart)
			}
		},
		ConnectStart: func(_, _ string) { connectStart = time.Now() },
		ConnectDone: func(_, _ string, _ error) {
			if !connectStart.IsZero() {
				timings["connect_ms"] = millisSince(connectStart)
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			if !tlsStart.IsZero() {
				timings["tls_ms"] = millisSince(tlsStart)
			}
		},
		WroteRequest: func(httptrace.WroteRequestInfo) { requestStart = time.Now() },
		GotFirstResponseByte: func() {
			if !requestStart.IsZero() {
				timings["ttfb_ms"] = millisSince(requestStart)
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Seconds() * 1000
	if err != nil {
		return map[string]any{
			"url":                target,
			"status_code":        0,
			"http_status":        0,
			"latency_ms":         elapsed,
			"body_bytes":         0,
			"timings":            timings,
			"error":              err.Error(),
			"error_type":         httpErrorType(err),
			"measurement_status": "error",
		}, nil
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, 64*1024)
	n, _ := io.Copy(io.Discard, limited)
	bodyBytes = n

	return map[string]any{
		"url":                target,
		"status_code":        resp.StatusCode,
		"http_status":        resp.StatusCode,
		"latency_ms":         elapsed,
		"body_bytes":         bodyBytes,
		"timings":            timings,
		"measurement_status": "ok",
	}, nil
}

type safeDialer struct {
	dialer net.Dialer
}

func (d *safeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedHTTPIP(ip) {
			return nil, fmt.Errorf("http target resolves to a blocked address")
		}
		return d.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if isBlockedHTTPIP(addr.IP) {
			continue
		}
		return d.dialer.DialContext(ctx, network, net.JoinHostPort(addr.IP.String(), port))
	}
	return nil, fmt.Errorf("http target resolves only to blocked addresses")
}

func isBlockedHTTPIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		if ip4[0] == 10 || (ip4[0] == 192 && ip4[1] == 168) {
			return true
		}
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return !(ip4[1] >= 20 && ip4[1] <= 23)
		}
	}
	return false
}

func millisSince(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000
}

func httpErrorType(err error) string {
	if err == context.DeadlineExceeded || strings.Contains(strings.ToLower(err.Error()), "timeout") {
		return "timeout"
	}
	return "error"
}

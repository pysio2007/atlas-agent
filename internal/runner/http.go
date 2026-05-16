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
	var bodyBytes int64
	timings := map[string]float64{}
	var srcAddr, dstAddr string
	var dnsStart, connectStart, tlsStart, requestStart time.Time
	dialer := &safeDialer{
		dialer: net.Dialer{Timeout: time.Duration(timeoutMs) * time.Millisecond},
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			srcAddr = conn.LocalAddr().String()
			dstAddr = conn.RemoteAddr().String()
			return conn, nil
		},
	}
	client := &http.Client{
		Timeout:   time.Duration(timeoutMs) * time.Millisecond,
		Transport: transport,
	}

	redirectCount := 0
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		redirectCount = len(via)
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		if !followRedirects {
			return http.ErrUseLastResponse
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return fmt.Errorf("http redirect scheme must be http or https")
		}
		return nil
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
			"method":             method,
			"scheme":             parsedURL.Scheme,
			"proto":              "tcp",
			"status_code":        0,
			"http_status":        0,
			"latency_ms":         elapsed,
			"total_ms":           elapsed,
			"body_bytes":         0,
			"timings":            timings,
			"src_addr":           srcAddr,
			"dst_addr":           dstAddr,
			"redirect_count":     redirectCount,
			"error":              err.Error(),
			"error_type":         httpErrorType(err),
			"measurement_status": "error",
		}, nil
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, 64*1024)
	transferStart := time.Now()
	n, _ := io.Copy(io.Discard, limited)
	transferMs := millisSince(transferStart)
	bodyBytes = n

	return map[string]any{
		"url":                target,
		"method":             method,
		"scheme":             parsedURL.Scheme,
		"proto":              "tcp",
		"http_protocol":      resp.Proto,
		"status_code":        resp.StatusCode,
		"http_status":        resp.StatusCode,
		"response_status":    resp.Status,
		"latency_ms":         elapsed,
		"total_ms":           elapsed,
		"transfer_ms":        transferMs,
		"body_bytes":         bodyBytes,
		"timings":            timings,
		"src_addr":           srcAddr,
		"dst_addr":           dstAddr,
		"redirect_count":     redirectCount,
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
		return d.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	addrs, err := lookupIPAddrWithDN42Fallback(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		return d.dialer.DialContext(ctx, network, net.JoinHostPort(addr.IP.String(), port))
	}
	return nil, fmt.Errorf("http target has no resolved addresses")
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

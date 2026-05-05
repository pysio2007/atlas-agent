package runner

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
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
			if n, err := toInt(v); err == nil {
				timeoutMs = n
			}
		}
		if v, ok := m["follow_redirects"]; ok {
			if b, ok := v.(bool); ok {
				followRedirects = b
			}
		}
	}

	var bodyBytes int64
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
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

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Seconds() * 1000
	if err != nil {
		return map[string]any{
			"url":        target,
			"status_code": 0,
			"latency_ms": elapsed,
			"body_bytes":  0,
			"error":      err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, 64*1024)
	n, _ := io.Copy(io.Discard, limited)
	bodyBytes = n

	return map[string]any{
		"url":         target,
		"status_code": resp.StatusCode,
		"latency_ms":  elapsed,
		"body_bytes":  bodyBytes,
	}, nil
}

package runner

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type PingRunner struct{}

var (
	rttLineRe   = regexp.MustCompile(`rtt min/avg/max/(?:mdev|stddev) = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms`)
	statsLineRe = regexp.MustCompile(`(\d+) packets transmitted, (\d+) received, ([\d.]+)% packet loss`)
)

func (p *PingRunner) Run(ctx context.Context, target string, options any) (any, error) {
	count := 4
	timeoutMs := 3000
	if err := validateCommandTarget(target); err != nil {
		return nil, err
	}

	if m, ok := options.(map[string]any); ok {
		if v, ok := m["count"]; ok {
			if n, err := ToInt(v); err == nil {
				count = n
			}
		}
		if v, ok := m["timeout_ms"]; ok {
			if n, err := ToInt(v); err == nil {
				timeoutMs = n
			}
		}
		if v, ok := m["timeout"]; ok {
			if n, err := ToInt(v); err == nil && n > 0 {
				timeoutMs = n * 1000
			}
		}
	}
	if count < 1 || count > 20 {
		return nil, fmt.Errorf("invalid ping count %d: must be 1-20", count)
	}
	if timeoutMs < 500 || timeoutMs > 30000 {
		return nil, fmt.Errorf("invalid ping timeout_ms %d: must be 500-30000", timeoutMs)
	}

	timeoutSeconds := (timeoutMs + 999) / 1000
	cmd := exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(count), "-W", strconv.Itoa(timeoutSeconds), target)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("ping execution failed: %w", err)
	}

	output := string(out)
	result := map[string]any{
		"target":     target,
		"count":      count,
		"timeout":    timeoutSeconds,
		"timeout_ms": timeoutMs,
	}

	if sm := statsLineRe.FindStringSubmatch(output); len(sm) == 4 {
		sent, _ := strconv.Atoi(sm[1])
		received, _ := strconv.Atoi(sm[2])
		loss, _ := strconv.ParseFloat(sm[3], 64)
		result["sent"] = sent
		result["received"] = received
		result["loss_percent"] = loss
	}

	if rm := rttLineRe.FindStringSubmatch(output); len(rm) == 5 {
		min, _ := strconv.ParseFloat(rm[1], 64)
		avg, _ := strconv.ParseFloat(rm[2], 64)
		max, _ := strconv.ParseFloat(rm[3], 64)
		mdev, _ := strconv.ParseFloat(rm[4], 64)
		result["min_rtt"] = min
		result["avg_rtt"] = avg
		result["max_rtt"] = max
		result["mdev_rtt"] = mdev
	}

	rtts := []float64{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "64 bytes from") || strings.Contains(line, "icmp_seq") {
			parts := strings.Split(line, "time=")
			if len(parts) < 2 {
				parts = strings.Split(line, "time=")
			}
			if len(parts) >= 2 {
				timeStr := strings.Split(parts[len(parts)-1], " ")[0]
				if v, err := strconv.ParseFloat(timeStr, 64); err == nil {
					rtts = append(rtts, v)
				}
			}
		}
	}
	result["rtts"] = rtts

	return result, nil
}

func ToInt(v any) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case float64:
		return int(n), nil
	case string:
		return strconv.Atoi(n)
	default:
		return 0, fmt.Errorf("cannot convert %T to int", v)
	}
}

func validateCommandTarget(target string) error {
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("target is required")
	}
	if strings.HasPrefix(strings.TrimSpace(target), "-") {
		return fmt.Errorf("invalid target: must not start with '-'")
	}
	return nil
}

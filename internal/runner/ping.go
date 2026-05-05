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
	rttLineRe   = regexp.MustCompile(`rtt min/avg/max/mdev = [\d.]+/([\d.]+)/([\d.]+)/[\d.]+ ms`)
	statsLineRe = regexp.MustCompile(`(\d+) packets transmitted, (\d+) received, ([\d.]+)% packet loss`)
)

func (p *PingRunner) Run(ctx context.Context, target string, options any) (any, error) {
	count := 4
	timeout := 3

	if m, ok := options.(map[string]any); ok {
		if v, ok := m["count"]; ok {
			if n, err := toInt(v); err == nil {
				count = n
			}
		}
		if v, ok := m["timeout"]; ok {
			if n, err := toInt(v); err == nil {
				timeout = n
			}
		}
	}

	cmd := exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(count), "-W", strconv.Itoa(timeout), target)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("ping execution failed: %w", err)
	}

	output := string(out)
	result := map[string]any{
		"target":  target,
		"count":   count,
		"timeout": timeout,
	}

	if sm := statsLineRe.FindStringSubmatch(output); len(sm) == 4 {
		sent, _ := strconv.Atoi(sm[1])
		received, _ := strconv.Atoi(sm[2])
		loss, _ := strconv.ParseFloat(sm[3], 64)
		result["sent"] = sent
		result["received"] = received
		result["loss_percent"] = loss
	}

	if rm := rttLineRe.FindStringSubmatch(output); len(rm) == 3 {
		avg, _ := strconv.ParseFloat(rm[1], 64)
		max, _ := strconv.ParseFloat(rm[2], 64)
		result["avg_rtt"] = avg
		result["max_rtt"] = max
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

func toInt(v any) (int, error) {
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

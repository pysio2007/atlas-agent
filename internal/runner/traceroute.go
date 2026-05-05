package runner

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type TracerouteRunner struct{}

var hopLineRe = regexp.MustCompile(`\s*(\d+)\s+(.+?)\s+([\d.]+)\s+ms(.*)`)

func (t *TracerouteRunner) Run(ctx context.Context, target string, options any) (any, error) {
	maxHops := 30

	if m, ok := options.(map[string]any); ok {
		if v, ok := m["max_hops"]; ok {
			if n, err := toInt(v); err == nil {
				maxHops = n
			}
		}
	}

	cmd := exec.CommandContext(ctx, "traceroute", "-m", strconv.Itoa(maxHops), "-w", "3", "-q", "3", target)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("traceroute execution failed: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	hops := []map[string]any{}

	for _, line := range lines {
		matches := hopLineRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		ttl, _ := strconv.Atoi(matches[1])
		ip := strings.TrimSpace(matches[2])
		rtt, _ := strconv.ParseFloat(matches[3], 64)

		rtts := []float64{rtt}
		remainder := matches[4]
		subMatches := hopLineRe.FindAllStringSubmatch(" "+remainder, -1)
		for _, sm := range subMatches {
			if r, err := strconv.ParseFloat(sm[3], 64); err == nil {
				rtts = append(rtts, r)
				if strings.TrimSpace(sm[2]) != "" && strings.TrimSpace(sm[2]) != "*" {
					ip = strings.TrimSpace(sm[2])
				}
			}
		}

		hop := map[string]any{
			"ttl":  ttl,
			"ip":   ip,
			"rtts": rtts,
		}
		hops = append(hops, hop)
	}

	return map[string]any{
		"target": target,
		"hops":   hops,
	}, nil
}

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

var rttTokenRe = regexp.MustCompile(`(?:(\S+)\s+)?([\d.]+)\s+ms`)

func (t *TracerouteRunner) Run(ctx context.Context, target string, options any) (any, error) {
	maxHops := 30
	proto := "udp"
	if err := validateCommandTarget(target); err != nil {
		return nil, err
	}

	if m, ok := options.(map[string]any); ok {
		if v, ok := m["max_hops"]; ok {
			if n, err := ToInt(v); err == nil {
				maxHops = n
			}
		}
		if v, ok := m["proto"].(string); ok && v != "" {
			proto = strings.ToLower(v)
		}
		if v, ok := m["protocol"].(string); ok && v != "" {
			proto = strings.ToLower(v)
		}
	}
	if maxHops < 1 || maxHops > 64 {
		return nil, fmt.Errorf("invalid traceroute max_hops %d: must be 1-64", maxHops)
	}
	if proto != "udp" && proto != "icmp" && proto != "tcp" {
		return nil, fmt.Errorf("invalid traceroute proto %s: must be udp, icmp, or tcp", proto)
	}

	args := []string{"-m", strconv.Itoa(maxHops), "-w", "3", "-q", "3"}
	switch proto {
	case "icmp":
		args = append(args, "-I")
	case "tcp":
		args = append(args, "-T")
	}
	args = append(args, target)
	cmd := exec.CommandContext(ctx, "traceroute", args...)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("traceroute execution failed: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	hops := []map[string]any{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ttl, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}

		body := strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
		probes := []map[string]any{}
		rtts := []float64{}
		ip := ""
		if strings.Contains(body, "*") && !strings.Contains(body, "ms") {
			for i := 0; i < strings.Count(body, "*"); i++ {
				probes = append(probes, map[string]any{"probe": i + 1, "result": "timeout", "x": "*"})
			}
		} else {
			matches := rttTokenRe.FindAllStringSubmatch(body, -1)
			for _, m := range matches {
				rtt, _ := strconv.ParseFloat(m[2], 64)
				rtts = append(rtts, rtt)
				addr := strings.TrimSpace(m[1])
				if addr != "" && addr != "*" {
					ip = addr
				}
				probe := map[string]any{"probe": len(probes) + 1, "result": "reply", "rtt": rtt, "rtt_ms": rtt}
				if addr != "" && addr != "*" {
					probe["from"] = addr
				}
				probes = append(probes, probe)
			}
		}
		for len(probes) < 3 && strings.Contains(body, "*") {
			probes = append(probes, map[string]any{"probe": len(probes) + 1, "result": "timeout", "x": "*"})
		}

		hop := map[string]any{
			"hop":    ttl,
			"ttl":    ttl,
			"ip":     ip,
			"addr":   ip,
			"result": probes,
			"rtts":   rtts,
		}
		hops = append(hops, hop)
	}

	return map[string]any{
		"target":   target,
		"max_hops": maxHops,
		"proto":    proto,
		"hops":     hops,
	}, nil
}

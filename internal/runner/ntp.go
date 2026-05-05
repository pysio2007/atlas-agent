package runner

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

type NTPRunner struct{}

func (n *NTPRunner) Run(ctx context.Context, target string, options any) (any, error) {
	timeoutMs := 5000
	if m, ok := options.(map[string]any); ok {
		if v, ok := m["timeout_ms"]; ok {
			if n, err := ToInt(v); err == nil {
				timeoutMs = n
			}
		}
	}
	if timeoutMs < 500 || timeoutMs > 30000 {
		return nil, fmt.Errorf("invalid ntp timeout_ms %d: must be 500-30000", timeoutMs)
	}

	host, port, err := splitHostPortDefault(target, "123")
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	addr := net.JoinHostPort(host, port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return measurementErrorResult(target, host, port, timeoutMs, nil, err), nil
	}

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", udpAddr.String())
	if err != nil {
		return measurementErrorResult(target, host, port, timeoutMs, nil, err), nil
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)); err != nil {
		return measurementErrorResult(target, host, port, timeoutMs, nil, err), nil
	}

	var req [48]byte
	req[0] = 0x23
	t1 := time.Now().UTC()
	writeNTPTime(req[40:48], t1)
	if _, err := conn.Write(req[:]); err != nil {
		return measurementErrorResult(target, host, port, timeoutMs, nil, err), nil
	}

	var resp [48]byte
	if _, err := conn.Read(resp[:]); err != nil {
		return measurementErrorResult(target, host, port, timeoutMs, nil, err), nil
	}
	t4 := time.Now().UTC()

	leap := int((resp[0] >> 6) & 0x03)
	version := int((resp[0] >> 3) & 0x07)
	mode := int(resp[0] & 0x07)
	stratum := int(resp[1])
	t2 := readNTPTime(resp[32:40])
	t3 := readNTPTime(resp[40:48])
	delayMs := ((t4.Sub(t1)).Seconds() - (t3.Sub(t2)).Seconds()) * 1000
	offsetMs := (((t2.Sub(t1)).Seconds() + (t3.Sub(t4)).Seconds()) / 2) * 1000

	return map[string]any{
		"target":             target,
		"host":               host,
		"port":               port,
		"timeout_ms":         timeoutMs,
		"offset_ms":          offsetMs,
		"delay_ms":           delayMs,
		"stratum":            stratum,
		"leap":               leap,
		"version":            version,
		"mode":               mode,
		"measurement_status": "ok",
	}, nil
}

func writeNTPTime(dst []byte, t time.Time) {
	const ntpEpochOffset = 2208988800
	secs := uint32(t.Unix() + ntpEpochOffset)
	frac := uint32(uint64(t.Nanosecond()) * (1 << 32) / 1e9)
	binary.BigEndian.PutUint32(dst[:4], secs)
	binary.BigEndian.PutUint32(dst[4:], frac)
}

func readNTPTime(src []byte) time.Time {
	const ntpEpochOffset = 2208988800
	secs := binary.BigEndian.Uint32(src[:4])
	frac := binary.BigEndian.Uint32(src[4:])
	unixSecs := int64(secs) - ntpEpochOffset
	nanos := (int64(frac) * 1e9) >> 32
	return time.Unix(unixSecs, nanos).UTC()
}

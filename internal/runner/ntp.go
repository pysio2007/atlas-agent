package runner

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
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

	addrs, err := lookupIPAddrWithDN42Fallback(ctx, host)
	if err != nil {
		return measurementErrorResult(target, host, port, timeoutMs, nil, err), nil
	}
	if len(addrs) == 0 {
		return measurementErrorResult(target, host, port, timeoutMs, nil, fmt.Errorf("no ip addresses found for %s", host)), nil
	}

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(addrs[0].IP.String(), port))
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
	nRead, err := conn.Read(resp[:])
	if err != nil {
		return measurementErrorResult(target, host, port, timeoutMs, nil, err), nil
	}
	if nRead < len(resp) {
		return measurementErrorResult(target, host, port, timeoutMs, nil, fmt.Errorf("short ntp response: %d bytes", nRead)), nil
	}
	t4 := time.Now().UTC()

	leap := int((resp[0] >> 6) & 0x03)
	version := int((resp[0] >> 3) & 0x07)
	mode := int(resp[0] & 0x07)
	stratum := int(resp[1])
	t2 := readNTPTime(resp[32:40])
	t3 := readNTPTime(resp[40:48])
	refTime := readNTPTime(resp[16:24])
	originTime := readNTPTime(resp[24:32])
	delayMs := ((t4.Sub(t1)).Seconds() - (t3.Sub(t2)).Seconds()) * 1000
	offsetMs := (((t2.Sub(t1)).Seconds() + (t3.Sub(t4)).Seconds()) / 2) * 1000

	result := map[string]any{
		"target":             target,
		"host":               host,
		"port":               port,
		"proto":              "udp",
		"src_addr":           conn.LocalAddr().String(),
		"dst_addr":           conn.RemoteAddr().String(),
		"timeout_ms":         timeoutMs,
		"offset_ms":          offsetMs,
		"delay_ms":           delayMs,
		"root_delay_ms":      ntpFixedPointMs(resp[4:8]),
		"root_dispersion_ms": ntpFixedPointMs(resp[8:12]),
		"reference_id":       ntpReferenceID(resp[12:16], stratum),
		"reference_time":     refTime.Format(time.RFC3339Nano),
		"origin_time":        originTime.Format(time.RFC3339Nano),
		"receive_time":       t2.Format(time.RFC3339Nano),
		"transmit_time":      t3.Format(time.RFC3339Nano),
		"destination_time":   t4.Format(time.RFC3339Nano),
		"stratum":            stratum,
		"leap":               leap,
		"version":            version,
		"mode":               mode,
		"measurement_status": "ok",
	}
	if mode != 4 {
		result["measurement_status"] = "error"
		result["error_type"] = "invalid_mode"
		result["error"] = fmt.Sprintf("unexpected NTP mode %d", mode)
	} else if stratum == 0 {
		result["measurement_status"] = "error"
		result["error_type"] = "kiss_of_death"
		result["error"] = "server returned stratum 0"
	} else if math.Abs(originTime.Sub(t1).Seconds()) > 1 {
		result["measurement_status"] = "error"
		result["error_type"] = "origin_mismatch"
		result["error"] = "server origin timestamp does not match request"
	}
	return result, nil
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

func ntpFixedPointMs(src []byte) float64 {
	if len(src) < 4 {
		return 0
	}
	value := binary.BigEndian.Uint32(src[:4])
	seconds := float64(value>>16) + float64(value&0xffff)/65536
	return seconds * 1000
}

func ntpReferenceID(src []byte, stratum int) string {
	if len(src) < 4 {
		return ""
	}
	if stratum <= 1 {
		text := strings.TrimSpace(string(src[:4]))
		if text != "" {
			return text
		}
	}
	return net.IPv4(src[0], src[1], src[2], src[3]).String() + "/" + strconv.FormatUint(uint64(binary.BigEndian.Uint32(src[:4])), 10)
}

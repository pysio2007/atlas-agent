package handler

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akaere/autopeer/atlas-agent/internal/runner"
	"github.com/akaere/autopeer/atlas-agent/internal/store"
	"github.com/sirupsen/logrus"
)

type SendFunc func(msg map[string]any)

type Handler struct {
	runners         map[string]runner.Runner
	store           *store.Store
	send            SendFunc
	log             *logrus.Logger
	jobs            chan map[string]any
	authFailed      func()
	runningJobs     int64
	droppedJobs     int64
	systemPlatform  string
	systemOS        string
	systemArch      string
	clockStatus     string
	lastError       string
	maxConcurrency  int64
	queueSize       int64
	jobTimeoutNanos int64
	workerNotify    chan struct{}
	mu              sync.Mutex
}

const (
	defaultConcurrency = 8
	maxConcurrency     = 64
	defaultQueueSize   = 64
	maxQueueSize       = 1024
	defaultJobTimeout  = 30 * time.Second
	resultMver         = "autopeer-atlas-agent-1"
)

type atlasJobMeta struct {
	SchemaVersion int
	MeasurementID string
	ResultID      string
	ProbeID       string
	Type          string
	Target        string
	AF            string
	Proto         string
}

func New(runners map[string]runner.Runner, s *store.Store, send SendFunc, log *logrus.Logger) *Handler {
	h := &Handler{
		runners:         runners,
		store:           s,
		send:            send,
		log:             log,
		jobs:            make(chan map[string]any, maxQueueSize),
		systemPlatform:  runtime.GOOS + "/" + runtime.GOARCH,
		systemOS:        runtime.GOOS,
		systemArch:      runtime.GOARCH,
		clockStatus:     "unknown",
		maxConcurrency:  defaultConcurrency,
		queueSize:       defaultQueueSize,
		jobTimeoutNanos: int64(defaultJobTimeout),
		workerNotify:    make(chan struct{}, 1),
	}
	for i := 0; i < maxConcurrency; i++ {
		go h.worker()
	}
	return h
}

func (h *Handler) SetClockStatus(status string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if strings.TrimSpace(status) != "" {
		h.clockStatus = status
	}
}

func (h *Handler) SetAuthFailedFunc(fn func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.authFailed = fn
}

func (h *Handler) Status() map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()

	return map[string]any{
		"queue_depth":         len(h.jobs),
		"queue_size":          atomic.LoadInt64(&h.queueSize),
		"queue_capacity":      cap(h.jobs),
		"running_jobs":        atomic.LoadInt64(&h.runningJobs),
		"dropped_jobs":        atomic.LoadInt64(&h.droppedJobs),
		"concurrency":         atomic.LoadInt64(&h.maxConcurrency),
		"job_timeout_seconds": int64(time.Duration(atomic.LoadInt64(&h.jobTimeoutNanos)) / time.Second),
		"platform":            h.systemPlatform,
		"os":                  h.systemOS,
		"arch":                h.systemArch,
		"clock_status":        h.clockStatus,
		"last_error":          h.lastError,
	}
}

func (h *Handler) HandleMessage(msg map[string]any) {
	msgType, _ := msg["type"].(string)

	switch msgType {
	case "atlas.auth_ack":
		h.handleAuthAck(msg)
	case "atlas.job":
		if int64(len(h.jobs)) >= atomic.LoadInt64(&h.queueSize) {
			atomic.AddInt64(&h.droppedJobs, 1)
			meta, _ := atlasJobMetaFromMessage(msg)
			now := time.Now()
			h.sendResult(meta, nil, fmt.Errorf("job queue full"), now, now)
			return
		}
		select {
		case h.jobs <- msg:
		default:
			atomic.AddInt64(&h.droppedJobs, 1)
			meta, _ := atlasJobMetaFromMessage(msg)
			now := time.Now()
			h.sendResult(meta, nil, fmt.Errorf("job queue full"), now, now)
		}
	default:
		h.log.WithField("type", msgType).Debug("unknown message type")
	}
}

func (h *Handler) worker() {
	for msg := range h.jobs {
		for atomic.LoadInt64(&h.runningJobs) >= atomic.LoadInt64(&h.maxConcurrency) {
			select {
			case <-h.workerNotify:
			case <-time.After(100 * time.Millisecond):
			}
		}
		atomic.AddInt64(&h.runningJobs, 1)
		h.handleJob(msg)
		atomic.AddInt64(&h.runningJobs, -1)
		h.notifyWorkers()
	}
}

func (h *Handler) notifyWorkers() {
	select {
	case h.workerNotify <- struct{}{}:
	default:
	}
}

func (h *Handler) handleAuthAck(msg map[string]any) {
	payload, _ := msg["payload"].(map[string]any)
	if payload == nil {
		h.log.Warn("auth_ack missing payload")
		return
	}
	success, _ := payload["success"].(bool)
	if !success {
		errStr, _ := payload["error"].(string)
		h.log.WithField("error", errStr).Error("atlas auth rejected")
		h.mu.Lock()
		authFailed := h.authFailed
		h.mu.Unlock()
		if authFailed != nil {
			authFailed()
		}
		return
	}
	probeID, _ := payload["probe_id"].(string)
	if probeID == "" {
		h.log.Warn("auth_ack missing probe_id")
		return
	}
	if err := h.store.SetProbeID(probeID); err != nil {
		h.log.WithError(err).Error("failed to store probe_id")
		return
	}
	h.applyPolicy(payload["policy"])
	h.log.WithField("probe_id", probeID).Info("authenticated")
}

func (h *Handler) applyPolicy(raw any) {
	policy, _ := raw.(map[string]any)
	if len(policy) == 0 {
		return
	}
	if n, err := runner.ToInt(policy["max_concurrency"]); err == nil && n > 0 {
		if n > maxConcurrency {
			n = maxConcurrency
		}
		atomic.StoreInt64(&h.maxConcurrency, int64(n))
	}
	if n, err := runner.ToInt(policy["queue_size"]); err == nil && n > 0 {
		if n > maxQueueSize {
			n = maxQueueSize
		}
		atomic.StoreInt64(&h.queueSize, int64(n))
	}
	if n, err := runner.ToInt(policy["job_timeout_seconds"]); err == nil && n > 0 {
		atomic.StoreInt64(&h.jobTimeoutNanos, int64(time.Duration(n)*time.Second))
	}
	h.notifyWorkers()
}

func (h *Handler) handleJob(msg map[string]any) {
	meta, payload := atlasJobMetaFromMessage(msg)
	if payload == nil {
		h.log.Warn("job missing payload")
		return
	}
	options := payload["options"]

	r, ok := h.runners[meta.Type]
	if !ok {
		now := time.Now()
		h.sendResult(meta, nil, fmt.Errorf("unknown job type: %s", meta.Type), now, now)
		return
	}

	startedAt := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), h.jobTimeout(meta.Type, msg, payload, options))
	defer cancel()
	result, err := r.Run(ctx, meta.Target, runnerOptions(meta, options))
	completedAt := time.Now()
	h.sendResult(meta, result, err, startedAt, completedAt)
}

func atlasJobMetaFromMessage(msg map[string]any) (atlasJobMeta, map[string]any) {
	payload, _ := msg["payload"].(map[string]any)
	meta := atlasJobMeta{SchemaVersion: 1}
	if id, _ := msg["id"].(string); id != "" {
		meta.ResultID = id
	}
	if payload == nil {
		return meta, nil
	}
	if v, err := runner.ToInt(payload["schema_version"]); err == nil && v > 0 {
		meta.SchemaVersion = v
	}
	if v, _ := payload["measurement_id"].(string); v != "" {
		meta.MeasurementID = v
	}
	if v, _ := payload["result_id"].(string); v != "" {
		meta.ResultID = v
	}
	if v, _ := payload["probe_id"].(string); v != "" {
		meta.ProbeID = v
	}
	meta.Type, _ = payload["type"].(string)
	meta.Target, _ = payload["target"].(string)
	meta.AF, _ = payload["af"].(string)
	meta.Proto, _ = payload["proto"].(string)
	if meta.Proto == "" {
		meta.Proto = defaultProto(meta.Type)
	}
	if meta.AF == "" {
		meta.AF = defaultAF(meta.Target)
	}
	return meta, payload
}

func (h *Handler) sendResult(meta atlasJobMeta, result any, err error, started, completed time.Time) {
	measurementStatus := "ok"
	errorType := ""
	srcAddr := ""
	dstAddr := ""
	if err != nil {
		measurementStatus = "error"
		errorType = classifyError(err)
		h.setLastError(err.Error())
	} else if m, ok := result.(map[string]any); ok {
		if v, ok := m["src_addr"].(string); ok {
			srcAddr = v
		}
		if v, ok := m["dst_addr"].(string); ok {
			dstAddr = v
		}
		if v, ok := m["measurement_status"].(string); ok && v != "" {
			measurementStatus = v
		}
		if v, ok := m["error_type"].(string); ok {
			errorType = v
		}
		if measurementStatus == "error" && errorType == "" {
			errorType = "error"
		}
		if measurementStatus == "error" {
			if v, ok := m["error"].(string); ok && v != "" {
				h.setLastError(v)
			}
		}
	}

	af := meta.AF
	if dstAddr != "" {
		if inferred := addressFamilyFromAddr(dstAddr); inferred != "" {
			af = inferred
		}
	}
	payload := map[string]any{
		"schema_version":     meta.SchemaVersion,
		"fw":                 1,
		"mver":               resultMver,
		"measurement_id":     meta.MeasurementID,
		"result_id":          meta.ResultID,
		"probe_id":           meta.ProbeID,
		"type":               meta.Type,
		"target":             meta.Target,
		"af":                 af,
		"proto":              meta.Proto,
		"timestamp":          completed.UTC().Unix(),
		"timestamp_rfc3339":  completed.UTC().Format(time.RFC3339),
		"agent_status":       agentStatus(err),
		"measurement_status": measurementStatus,
		"error_type":         errorType,
		"success":            err == nil && measurementStatus != "error",
		"started_at":         started.UTC().Format(time.RFC3339),
		"completed_at":       completed.UTC().Format(time.RFC3339),
	}
	if msmID, ok := numericAtlasID(meta.MeasurementID); ok {
		payload["msm_id"] = msmID
	} else if meta.MeasurementID != "" {
		payload["autopeer_msm_id"] = meta.MeasurementID
	}
	if prbID, ok := numericAtlasID(meta.ProbeID); ok {
		payload["prb_id"] = prbID
	} else if meta.ProbeID != "" {
		payload["autopeer_prb_id"] = meta.ProbeID
	}
	if srcAddr != "" {
		payload["src_addr"] = srcAddr
		payload["from"] = srcAddr
	}
	if dstAddr != "" {
		payload["dst_addr"] = dstAddr
	}

	if err != nil {
		payload["error"] = err.Error()
	} else {
		payload["result"] = result
	}

	msg := map[string]any{
		"type":    "atlas.result",
		"id":      meta.ResultID,
		"payload": payload,
	}

	h.send(msg)
}

func defaultProto(jobType string) string {
	switch jobType {
	case "ping":
		return "icmp"
	case "traceroute":
		return "udp"
	case "dns":
		return "udp"
	case "http":
		return "tcp"
	case "tls":
		return "tcp"
	case "ntp":
		return "udp"
	default:
		return ""
	}
}

func defaultAF(target string) string {
	if addressFamilyFromAddr(target) == "6" {
		return "6"
	}
	if addressFamilyFromAddr(target) == "4" {
		return "4"
	}
	return ""
}

func runnerOptions(meta atlasJobMeta, options any) any {
	if meta.Proto == "" {
		return options
	}
	m, ok := options.(map[string]any)
	if !ok {
		return options
	}
	if _, exists := m["proto"]; exists {
		return options
	}
	copy := make(map[string]any, len(m)+1)
	for k, v := range m {
		copy[k] = v
	}
	copy["proto"] = meta.Proto
	return copy
}

func numericAtlasID(id string) (int64, bool) {
	n, err := strconv.ParseInt(id, 10, 64)
	return n, err == nil
}

func addressFamilyFromAddr(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return "4"
		}
		return "6"
	}
	return ""
}

func (h *Handler) jobTimeout(jobType string, msg, payload map[string]any, options any) time.Duration {
	deadlineValue, _ := payload["deadline"].(string)
	if deadlineValue == "" {
		deadlineValue, _ = msg["deadline"].(string)
	}
	if deadlineValue != "" {
		if deadline, err := time.Parse(time.RFC3339Nano, deadlineValue); err == nil {
			if d := time.Until(deadline); d > 0 {
				return d
			}
			return time.Millisecond
		}
	}
	if m, ok := options.(map[string]any); ok {
		if v, ok := m["timeout_ms"]; ok {
			if n, err := runner.ToInt(v); err == nil && n > 0 {
				count := 1
				if c, ok := m["count"]; ok {
					if parsed, err := runner.ToInt(c); err == nil && parsed > 0 {
						count = parsed
					}
				}
				return time.Duration(n*count)*time.Millisecond + 2*time.Second
			}
		}
		if jobType == "ping" {
			if v, ok := m["timeout"]; ok {
				if n, err := runner.ToInt(v); err == nil && n > 0 {
					count := 4
					if c, ok := m["count"]; ok {
						if parsed, err := runner.ToInt(c); err == nil && parsed > 0 {
							count = parsed
						}
					}
					return time.Duration(n*count)*time.Second + 2*time.Second
				}
			}
		}
	}
	return time.Duration(atomic.LoadInt64(&h.jobTimeoutNanos))
}

func agentStatus(err error) string {
	if err == nil {
		return "ok"
	}
	if errorsIsDeadline(err) {
		return "timeout"
	}
	return "error"
}

func classifyError(err error) string {
	if err == nil {
		return ""
	}
	if errorsIsDeadline(err) {
		return "timeout"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "invalid") {
		return "validation"
	}
	return "error"
}

func errorsIsDeadline(err error) bool {
	return err == context.DeadlineExceeded || strings.Contains(strings.ToLower(err.Error()), "timeout")
}

func (h *Handler) setLastError(msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastError = msg
}

package handler

import (
	"context"
	"fmt"
	"runtime"
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
	runners        map[string]runner.Runner
	store          *store.Store
	send           SendFunc
	log            *logrus.Logger
	jobs           chan map[string]any
	authFailed     func()
	runningJobs    int64
	droppedJobs    int64
	systemPlatform string
	systemOS       string
	systemArch     string
	clockStatus    string
	lastError      string
	mu             sync.Mutex
}

const (
	defaultConcurrency = 8
	defaultQueueSize   = 64
	defaultJobTimeout  = 30 * time.Second
)

func New(runners map[string]runner.Runner, s *store.Store, send SendFunc, log *logrus.Logger) *Handler {
	h := &Handler{
		runners:        runners,
		store:          s,
		send:           send,
		log:            log,
		jobs:           make(chan map[string]any, defaultQueueSize),
		systemPlatform: runtime.GOOS + "/" + runtime.GOARCH,
		systemOS:       runtime.GOOS,
		systemArch:     runtime.GOARCH,
		clockStatus:    "unknown",
	}
	for i := 0; i < defaultConcurrency; i++ {
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
		"queue_depth":  len(h.jobs),
		"queue_size":   cap(h.jobs),
		"running_jobs": atomic.LoadInt64(&h.runningJobs),
		"dropped_jobs": atomic.LoadInt64(&h.droppedJobs),
		"concurrency":  defaultConcurrency,
		"platform":     h.systemPlatform,
		"os":           h.systemOS,
		"arch":         h.systemArch,
		"clock_status": h.clockStatus,
		"last_error":   h.lastError,
	}
}

func (h *Handler) HandleMessage(msg map[string]any) {
	msgType, _ := msg["type"].(string)

	switch msgType {
	case "atlas.auth_ack":
		h.handleAuthAck(msg)
	case "atlas.job":
		select {
		case h.jobs <- msg:
		default:
			atomic.AddInt64(&h.droppedJobs, 1)
			resultID, _ := msg["id"].(string)
			h.sendResult(resultID, "", "", nil, fmt.Errorf("job queue full"), time.Now(), time.Now())
		}
	default:
		h.log.WithField("type", msgType).Debug("unknown message type")
	}
}

func (h *Handler) worker() {
	for msg := range h.jobs {
		atomic.AddInt64(&h.runningJobs, 1)
		h.handleJob(msg)
		atomic.AddInt64(&h.runningJobs, -1)
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
	h.log.WithField("probe_id", probeID).Info("authenticated")
}

func (h *Handler) handleJob(msg map[string]any) {
	resultID, _ := msg["id"].(string)
	payload, _ := msg["payload"].(map[string]any)
	if payload == nil {
		h.log.Warn("job missing payload")
		return
	}
	jobType, _ := payload["type"].(string)
	target, _ := payload["target"].(string)
	options := payload["options"]

	r, ok := h.runners[jobType]
	if !ok {
		now := time.Now()
		h.sendResult(resultID, jobType, target, nil, fmt.Errorf("unknown job type: %s", jobType), now, now)
		return
	}

	startedAt := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), h.jobTimeout(jobType, msg, payload, options))
	defer cancel()
	result, err := r.Run(ctx, target, options)
	completedAt := time.Now()
	h.sendResult(resultID, jobType, target, result, err, startedAt, completedAt)
}

func (h *Handler) sendResult(resultID, jobType, target string, result any, err error, started, completed time.Time) {
	measurementStatus := "ok"
	errorType := ""
	if err != nil {
		measurementStatus = "error"
		errorType = classifyError(err)
		h.setLastError(err.Error())
	} else if m, ok := result.(map[string]any); ok {
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

	payload := map[string]any{
		"schema_version":     1,
		"result_id":          resultID,
		"type":               jobType,
		"target":             target,
		"timestamp":          completed.UTC().Format(time.RFC3339),
		"agent_status":       agentStatus(err),
		"measurement_status": measurementStatus,
		"error_type":         errorType,
		"success":            err == nil && measurementStatus != "error",
		"started_at":         started.UTC().Format(time.RFC3339),
		"completed_at":       completed.UTC().Format(time.RFC3339),
	}

	if err != nil {
		payload["error"] = err.Error()
	} else {
		payload["result"] = result
	}

	msg := map[string]any{
		"type":    "atlas.result",
		"id":      resultID,
		"payload": payload,
	}

	h.send(msg)
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
	return defaultJobTimeout
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

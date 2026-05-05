package handler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/akaere/autopeer/atlas-agent/internal/runner"
	"github.com/akaere/autopeer/atlas-agent/internal/store"
	"github.com/sirupsen/logrus"
)

type SendFunc func(msg map[string]any)

type Handler struct {
	runners map[string]runner.Runner
	store   *store.Store
	send    SendFunc
	log     *logrus.Logger
	mu      sync.Mutex
}

func New(runners map[string]runner.Runner, s *store.Store, send SendFunc, log *logrus.Logger) *Handler {
	return &Handler{
		runners: runners,
		store:   s,
		send:    send,
		log:     log,
	}
}

func (h *Handler) HandleMessage(msg map[string]any) {
	msgType, _ := msg["type"].(string)

	switch msgType {
	case "atlas.auth_ack":
		h.handleAuthAck(msg)
	case "atlas.job":
		go h.handleJob(msg)
	default:
		h.log.WithField("type", msgType).Debug("unknown message type")
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
		h.sendResult(resultID, nil, fmt.Errorf("unknown job type: %s", jobType))
		return
	}

	startedAt := time.Now()
	result, err := r.Run(context.Background(), target, options)
	completedAt := time.Now()
	h.sendResult(resultID, result, err, startedAt, completedAt)
}

func (h *Handler) sendResult(resultID string, result any, err error, startedAt ...time.Time) {
	started := time.Time{}
	completed := time.Now()
	if len(startedAt) > 0 {
		started = startedAt[0]
		completed = time.Now()
	}

	payload := map[string]any{
		"result_id":    resultID,
		"success":      err == nil,
		"started_at":   started.Format(time.RFC3339),
		"completed_at": completed.Format(time.RFC3339),
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

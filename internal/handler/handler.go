package handler

import (
	"context"
	"fmt"
	"sync"

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
	probeID, _ := msg["probe_id"].(string)
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
	jobID, _ := msg["job_id"].(string)
	jobType, _ := msg["job_type"].(string)
	target, _ := msg["target"].(string)
	options := msg["options"]

	r, ok := h.runners[jobType]
	if !ok {
		h.sendResult(jobID, jobType, target, nil, fmt.Errorf("unknown job type: %s", jobType))
		return
	}

	result, err := r.Run(context.Background(), target, options)
	h.sendResult(jobID, jobType, target, result, err)
}

func (h *Handler) sendResult(jobID, jobType, target string, result any, err error) {
	msg := map[string]any{
		"type":     "atlas.result",
		"job_id":   jobID,
		"job_type": jobType,
		"target":   target,
	}

	if err != nil {
		msg["error"] = err.Error()
	} else {
		msg["result"] = result
	}

	h.send(msg)
}

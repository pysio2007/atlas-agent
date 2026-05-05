package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/akaere/autopeer/atlas-agent/internal/config"
	"github.com/akaere/autopeer/atlas-agent/internal/handler"
	"github.com/akaere/autopeer/atlas-agent/internal/runner"
	"github.com/akaere/autopeer/atlas-agent/internal/store"
	"github.com/akaere/autopeer/atlas-agent/internal/ws"
	"github.com/sirupsen/logrus"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.WithError(err).Fatal("failed to load config")
	}

	s, err := store.Open(cfg.StorePath, log)
	if err != nil {
		log.WithError(err).Fatal("failed to open store")
	}
	defer s.Close()

	runners := map[string]runner.Runner{
		"ping":       &runner.PingRunner{},
		"traceroute": &runner.TracerouteRunner{},
		"dns":        &runner.DNSRunner{},
		"http":       &runner.HTTPRunner{},
	}

	var client *ws.Client

	h := handler.New(runners, s, func(msg map[string]any) {
		client.Send(msg)
	}, log)

	client = ws.NewClient(cfg, s, h, log)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.WithField("signal", sig.String()).Info("received signal, shutting down")
		cancel()
	}()

	if err := client.Run(ctx); err != nil && ctx.Err() == nil {
		log.WithError(err).Fatal("client exited with error")
	}

	log.Info("shutdown complete")
}

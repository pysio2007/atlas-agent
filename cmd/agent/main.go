package main

import (
	"context"
	"flag"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

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
		"tls":        &runner.TLSRunner{},
		"ntp":        &runner.NTPRunner{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	capabilityReport := runner.DetectCapabilities(ctx)
	cancel()
	clockStatus := checkClockStatus(log)

	ipv4Reachable := checkPing(log, "172.20.0.53")
	dn42DNSWorks := checkDN42DNSResolve(log, "wiki.dn42")
	systemDNSWorks := checkSystemDNSResolve(log, "wiki.dn42")

	log.WithFields(logrus.Fields{
		"dn42_ipv4_reachable": ipv4Reachable,
		"dn42_dns_works":      dn42DNSWorks,
		"system_dns_works":    systemDNSWorks,
		"capabilities":        capabilityReport.Capabilities,
		"capability_versions": capabilityReport.Versions,
		"platform":            runtime.GOOS + "/" + runtime.GOARCH,
		"os":                  runtime.GOOS,
		"arch":                runtime.GOARCH,
		"clock_status":        clockStatus,
	}).Info("connectivity check complete")

	var client *ws.Client

	h := handler.New(runners, s, func(msg map[string]any) {
		client.Send(msg)
	}, log)
	h.SetClockStatus(clockStatus)

	client = ws.NewClient(cfg, s, h, log)
	client.SetCapabilities(capabilityReport.Capabilities, capabilityReport.Versions)
	h.SetAuthFailedFunc(client.Close)
	client.SetStatusProvider(h)
	client.SetConnectivity(ipv4Reachable, dn42DNSWorks, systemDNSWorks)

	ctx, cancel = context.WithCancel(context.Background())
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

func checkPing(log *logrus.Logger, target string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "3", target)
	_, err := cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).WithField("target", target).Debug("ping check failed")
		return false
	}
	return true
}

func checkDN42DNSResolve(log *logrus.Logger, domain string) bool {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "172.20.0.53:53")
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := r.LookupHost(ctx, domain)
	if err != nil {
		log.WithError(err).WithField("domain", domain).Debug("DN42 DNS resolve failed")
		return false
	}
	return true
}

func checkSystemDNSResolve(log *logrus.Logger, domain string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		log.WithError(err).WithField("domain", domain).Debug("system DNS resolve failed")
		return false
	}
	return true
}

func checkClockStatus(log *logrus.Logger) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).Debug("clock status check failed")
		return "unknown"
	}
	status := strings.TrimSpace(string(out))
	switch strings.ToLower(status) {
	case "yes":
		return "synchronized"
	case "no":
		return "unsynchronized"
	case "":
		return "unknown"
	default:
		return status
	}
}

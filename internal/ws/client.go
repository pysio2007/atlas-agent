package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/akaere/autopeer/atlas-agent/internal/config"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type MessageHandler interface {
	HandleMessage(msg map[string]any)
}

type Store interface {
	GetProbeID() (string, error)
	SetProbeID(id string) error
}

type StatusProvider interface {
	Status() map[string]any
}

type Client struct {
	cfg     *config.Config
	store   Store
	handler MessageHandler
	status  StatusProvider
	log     *logrus.Logger

	conn                 *websocket.Conn
	connMu               sync.Mutex
	sendCh               chan map[string]any
	declaredCapabilities []string
	capabilityVersions   map[string]string

	dn42IPv4Reachable bool
	dn42DNSWorks      bool
	systemDNSWorks    bool
	dn42IPv4          string
	dn42IPv6          string
}

func NewClient(cfg *config.Config, s Store, h MessageHandler, log *logrus.Logger) *Client {
	return &Client{
		cfg:     cfg,
		store:   s,
		handler: h,
		log:     log,
		sendCh:  make(chan map[string]any, 256),
	}
}

func (c *Client) SetStatusProvider(status StatusProvider) {
	c.status = status
}

func (c *Client) SetCapabilities(capabilities []string, versions map[string]string) {
	if len(capabilities) > 0 {
		c.declaredCapabilities = append([]string(nil), capabilities...)
	}
	if len(versions) > 0 {
		c.capabilityVersions = make(map[string]string, len(versions))
		for k, v := range versions {
			c.capabilityVersions[k] = v
		}
	}
}

func (c *Client) SetConnectivity(ipv4Reachable, dn42DNS, systemDNS bool) {
	c.dn42IPv4Reachable = ipv4Reachable
	c.dn42DNSWorks = dn42DNS
	c.systemDNSWorks = systemDNS
}

func (c *Client) Run(ctx context.Context) error {
	for {
		err := c.connectAndServe(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.log.WithError(err).Warn("disconnected, reconnecting...")
		backoff := time.Duration(c.cfg.ReconnectMaxSecs) * time.Second
		c.exponentialBackoff(ctx, backoff)
	}
}

func (c *Client) connectAndServe(ctx context.Context) error {
	header := http.Header{}
	header.Set("X-Atlas-Token", c.cfg.Token)

	dialer := websocket.DefaultDialer
	conn, _, err := dialer.DialContext(ctx, c.cfg.CenterURL, header)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()

	c.log.Info("connected to center")

	if err := c.sendAuth(conn); err != nil {
		conn.Close()
		return fmt.Errorf("auth send failed: %w", err)
	}

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 3)

	go c.readPump(conn, errCh)
	go c.writePump(connCtx, conn, errCh)
	go c.heartbeatLoop(connCtx, conn, errCh)

	select {
	case err := <-errCh:
		cancel()
		conn.Close()
		return err
	case <-ctx.Done():
		cancel()
		conn.Close()
		return ctx.Err()
	}
}

func (c *Client) sendAuth(conn *websocket.Conn) error {
	dn42IPv4, dn42IPv6 := c.fetchDN42IPs()
	c.dn42IPv4 = dn42IPv4
	c.dn42IPv6 = dn42IPv6
	publicIPv4 := c.fetchPlainIP("https://api-ipv4.ip.sb/ip")
	publicIPv6 := c.fetchPlainIP("https://api-ipv6.ip.sb/ip")

	probeID, err := c.store.GetProbeID()
	if err != nil {
		c.log.WithError(err).Warn("failed to load stored probe_id")
	}

	payload := map[string]any{
		"token":               c.cfg.Token,
		"version":             "1.0.0",
		"dn42_ipv4":           dn42IPv4,
		"dn42_ipv6":           dn42IPv6,
		"public_ip_v4":        publicIPv4,
		"public_ip_v6":        publicIPv6,
		"probe_id":            probeID,
		"dn42_ipv4_reachable": c.dn42IPv4Reachable,
		"dn42_dns_works":      c.dn42DNSWorks,
		"system_dns_works":    c.systemDNSWorks,
		"capabilities":        c.capabilities(),
		"capability_versions": c.capabilityVersionsCopy(),
	}
	if c.status != nil {
		for k, v := range c.status.Status() {
			payload[k] = v
		}
	}

	msg := map[string]any{
		"type":    "atlas.auth",
		"payload": payload,
	}

	return c.writeJSON(conn, msg)
}

func (c *Client) readPump(conn *websocket.Conn, errCh chan<- error) {
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			errCh <- fmt.Errorf("read: %w", err)
			return
		}

		var msg map[string]any
		if err := json.Unmarshal(message, &msg); err != nil {
			c.log.WithError(err).Warn("failed to unmarshal message")
			continue
		}

		c.handler.HandleMessage(msg)
	}
}

func (c *Client) writePump(ctx context.Context, conn *websocket.Conn, errCh chan<- error) {
	for {
		select {
		case msg := <-c.sendCh:
			if err := c.writeJSON(conn, msg); err != nil {
				errCh <- fmt.Errorf("write: %w", err)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (c *Client) heartbeatLoop(ctx context.Context, conn *websocket.Conn, errCh chan<- error) {
	ticker := time.NewTicker(c.cfg.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			probeID, err := c.store.GetProbeID()
			if err != nil {
				c.log.WithError(err).Warn("failed to load stored probe_id")
			}
			payload := map[string]any{
				"probe_id":            probeID,
				"version":             "1.0.0",
				"dn42_ipv4":           c.dn42IPv4,
				"dn42_ipv6":           c.dn42IPv6,
				"capabilities":        c.capabilities(),
				"capability_versions": c.capabilityVersionsCopy(),
			}
			if c.status != nil {
				for k, v := range c.status.Status() {
					payload[k] = v
				}
			}
			msg := map[string]any{
				"type":    "atlas.heartbeat",
				"payload": payload,
			}
			if err := c.writeJSON(conn, msg); err != nil {
				errCh <- fmt.Errorf("heartbeat: %w", err)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (c *Client) Send(msg map[string]any) {
	select {
	case c.sendCh <- msg:
	default:
		c.log.WithField("type", msg["type"]).Warn("send queue full, dropping message")
	}
}

func (c *Client) writeJSON(conn *websocket.Conn, v any) error {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	return conn.WriteJSON(v)
}

func (c *Client) Close() {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

func (c *Client) capabilities() []string {
	if len(c.declaredCapabilities) == 0 {
		return []string{"ping", "traceroute", "dns", "http", "tls", "sslcert", "ntp"}
	}
	capabilities := append([]string(nil), c.declaredCapabilities...)
	for _, capability := range capabilities {
		if capability == "tls" {
			return append(capabilities, "sslcert")
		}
	}
	return capabilities
}

func (c *Client) capabilityVersionsCopy() map[string]string {
	if len(c.capabilityVersions) == 0 {
		return map[string]string{}
	}
	copyMap := make(map[string]string, len(c.capabilityVersions))
	for k, v := range c.capabilityVersions {
		copyMap[k] = v
	}
	return copyMap
}

type myipResponse struct {
	IP      string `json:"ip"`
	IsDN42  bool   `json:"is_dn42"`
	Network string `json:"network"`
	Country string `json:"country"`
}

func (c *Client) fetchDN42IPs() (string, string) {
	var dn42IPv4, dn42IPv6 string

	if ip, ok := c.fetchMyIP("http://172.23.78.131/myip"); ok {
		parsed := net.ParseIP(ip)
		if parsed != nil && parsed.To4() != nil {
			dn42IPv4 = ip
		}
	}

	if ip, ok := c.fetchMyIP("http://[fd0d:81ba:3563::10:4]/myip"); ok {
		parsed := net.ParseIP(ip)
		if parsed != nil && parsed.To4() == nil {
			dn42IPv6 = ip
		}
	}

	c.log.WithFields(logrus.Fields{
		"dn42_ipv4": dn42IPv4,
		"dn42_ipv6": dn42IPv6,
	}).Info("fetched DN42 IPs from myip endpoint")

	return dn42IPv4, dn42IPv6
}

func (c *Client) fetchMyIP(endpoint string) (string, bool) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(endpoint)
	if err != nil {
		c.log.WithError(err).WithField("endpoint", endpoint).Debug("myip request failed")
		return "", false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil {
		return "", false
	}

	var result myipResponse
	if err := json.Unmarshal(body, &result); err != nil {
		c.log.WithError(err).WithField("endpoint", endpoint).Debug("myip parse failed")
		return "", false
	}

	if !result.IsDN42 || result.IP == "" {
		return "", false
	}

	return result.IP, true
}

func (c *Client) fetchPlainIP(endpoint string) string {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "AutoPeer-Atlas-Agent/1.0")
	resp, err := client.Do(req)
	if err != nil {
		c.log.WithError(err).WithField("endpoint", endpoint).Debug("public IP request failed")
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}

	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

func (c *Client) exponentialBackoff(ctx context.Context, max time.Duration) {
	attempt := 0
	for {
		wait := time.Duration(1<<uint(attempt)) * time.Second
		if wait > max {
			wait = max
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
			attempt++
			return
		}
	}
}

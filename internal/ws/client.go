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
	GetProbeID() string
	SetProbeID(id string) error
}

type Client struct {
	cfg     *config.Config
	store   Store
	handler MessageHandler
	log     *logrus.Logger

	conn   *websocket.Conn
	connMu sync.Mutex
	sendCh chan map[string]any

	dn42IPv4 string
	dn42IPv6 string
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

	errCh := make(chan error, 3)

	go c.readPump(conn, errCh)
	go c.writePump(conn, errCh)
	go c.heartbeatLoop(ctx, conn, errCh)

	select {
	case err := <-errCh:
		conn.Close()
		return err
	case <-ctx.Done():
		conn.Close()
		return ctx.Err()
	}
}

func (c *Client) sendAuth(conn *websocket.Conn) error {
	dn42IPv4, dn42IPv6 := c.detectDN42IPs()
	c.dn42IPv4 = dn42IPv4
	c.dn42IPv6 = dn42IPv6
	publicIP := c.detectPublicIP()

	payload := map[string]any{
		"token":     c.cfg.Token,
		"version":   "1.0.0",
		"dn42_ipv4": dn42IPv4,
		"dn42_ipv6": dn42IPv6,
		"public_ip": publicIP,
		"probe_id":  c.store.GetProbeID(),
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

func (c *Client) writePump(conn *websocket.Conn, errCh chan<- error) {
	for msg := range c.sendCh {
		if err := c.writeJSON(conn, msg); err != nil {
			errCh <- fmt.Errorf("write: %w", err)
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
			msg := map[string]any{
				"type": "atlas.heartbeat",
				"payload": map[string]any{
					"probe_id":  c.store.GetProbeID(),
					"version":   "1.0.0",
					"dn42_ipv4": c.dn42IPv4,
					"dn42_ipv6": c.dn42IPv6,
				},
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
	c.sendCh <- msg
}

func (c *Client) writeJSON(conn *websocket.Conn, v any) error {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return conn.WriteJSON(v)
}

func (c *Client) detectDN42IPs() (string, string) {
	var dn42IPv4, dn42IPv6 string

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}

	_, dn42Net, _ := net.ParseCIDR("172.20.0.0/14")
	_, dn42Net10, _ := net.ParseCIDR("10.0.0.0/8")
	_, dn42Net6, _ := net.ParseCIDR("fd00::/8")

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}

			if ip.To4() != nil {
				if dn42Net.Contains(ip) || dn42Net10.Contains(ip) {
					if dn42IPv4 == "" || dn42Net.Contains(ip) {
						dn42IPv4 = ip.String()
					}
				}
			} else {
				if dn42Net6.Contains(ip) && !ip.IsLinkLocalUnicast() {
					dn42IPv6 = ip.String()
				}
			}
		}
	}

	return dn42IPv4, dn42IPv6
}

func (c *Client) detectPublicIP() string {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		c.log.WithError(err).Warn("failed to detect public IP")
		return ""
	}
	defer resp.Body.Close()

	ip, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(ip))
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

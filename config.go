package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
)

type Config struct {
	Mode            string `json:"mode"`
	Listen          string `json:"listen"`
	TunnelListen    string `json:"tunnel_listen,omitempty"`
	Peer            string `json:"peer,omitempty"`
	Target          string `json:"target,omitempty"`
	ServerName      string `json:"server_name,omitempty"`
	CA              string `json:"ca"`
	Cert            string `json:"cert"`
	Key             string `json:"key"`
	Admin           string `json:"admin"`
	MaxConnections  int    `json:"max_connections"`
	IdleSeconds     int    `json:"idle_seconds"`
	UDPQueuePackets int    `json:"udp_queue_packets,omitempty"`
}

func loadConfig(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return c, errors.New("configuration must contain exactly one JSON object")
	}
	if c.Mode != "edge" && c.Mode != "relay" && c.Mode != "reverse-edge" && c.Mode != "reverse-relay" && c.Mode != "udp-edge" && c.Mode != "udp-relay" {
		return c, errors.New("unknown tunnel mode")
	}
	if c.MaxConnections < 1 || c.MaxConnections > 10000 {
		return c, errors.New("max_connections must be 1..10000")
	}
	if c.IdleSeconds < 1 || c.IdleSeconds > 86400 {
		return c, errors.New("idle_seconds must be 1..86400")
	}
	if c.UDPQueuePackets == 0 {
		c.UDPQueuePackets = 8
	}
	if c.UDPQueuePackets < 1 || c.UDPQueuePackets > 64 {
		return c, errors.New("udp_queue_packets must be 1..64")
	}
	addresses := []string{c.Admin}
	if c.Mode != "reverse-relay" {
		addresses = append(addresses, c.Listen)
	}
	switch c.Mode {
	case "edge", "udp-edge":
		if c.ServerName == "" || c.Target != "" {
			return c, errors.New("edge requires server_name and must not set target")
		}
		addresses = append(addresses, c.Peer)
	case "relay", "udp-relay":
		if c.Peer != "" {
			return c, errors.New("relay must not set peer")
		}
		addresses = append(addresses, c.Target)
	case "reverse-edge":
		if c.Target != "" || c.Peer != "" {
			return c, errors.New("reverse-edge must not set target or peer")
		}
		addresses = append(addresses, c.TunnelListen)
	case "reverse-relay":
		if c.Listen != "" || c.TunnelListen != "" || c.ServerName == "" {
			return c, errors.New("reverse-relay requires server_name and no listening address")
		}
		addresses = append(addresses, c.Peer, c.Target)
	}
	if c.Mode != "reverse-edge" && c.TunnelListen != "" {
		return c, errors.New("tunnel_listen is only valid for reverse-edge")
	}
	for _, a := range addresses {
		if err := validAddress(a); err != nil {
			return c, err
		}
	}
	host, _, _ := net.SplitHostPort(c.Admin)
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return c, errors.New("admin must bind to a numeric loopback address")
	}
	for _, p := range []*string{&c.CA, &c.Cert, &c.Key} {
		if *p == "" {
			return c, errors.New("ca, cert and key are required")
		}
		if !filepath.IsAbs(*p) {
			*p = filepath.Join(filepath.Dir(path), *p)
		}
	}
	return c, nil
}

func validAddress(a string) error {
	h, p, err := net.SplitHostPort(a)
	if err != nil || h == "" || p == "" {
		return fmt.Errorf("expected explicit host:port, got %q", a)
	}
	// Numeric ports make configuration errors fail before listeners start.
	var port int
	for _, ch := range p {
		if ch < '0' || ch > '9' {
			return fmt.Errorf("invalid port in %q", a)
		}
		port = port*10 + int(ch-'0')
		if port > 65535 {
			return fmt.Errorf("invalid port in %q", a)
		}
	}
	if port < 1 {
		return fmt.Errorf("invalid port in %q", a)
	}
	return nil
}

func tlsConfig(c Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(c.CA)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("no CA certificates found")
	}
	alpn := "tunnellab/0.1"
	if c.Mode == "reverse-edge" || c.Mode == "reverse-relay" {
		alpn = reverseALPN
	}
	if c.Mode == "udp-edge" || c.Mode == "udp-relay" {
		alpn = udpALPN
	}
	t := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{alpn}}
	if c.Mode == "relay" || c.Mode == "reverse-edge" || c.Mode == "udp-relay" {
		t.NextProtos = append(t.NextProtos, probeALPN)
		t.ClientAuth = tls.RequireAndVerifyClientCert
		t.ClientCAs = pool
		if c.Mode == "reverse-edge" {
			t.VerifyConnection = func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("missing relay identity")
				}
				return cs.PeerCertificates[0].VerifyHostname("relay.tunnellab.local")
			}
		}
	} else {
		t.RootCAs = pool
		t.ServerName = c.ServerName
	}
	return t, nil
}

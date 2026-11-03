package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"
)

// This header is exchanged only AFTER mutually authenticated TLS. It is not
// HTTP camouflage. Both peers must explicitly select encrypted-preface.
var protocolMagic = []byte{'T', 'L', 'A', 'B', 1}

func protocolHeader(protocol string) ([]byte, error) {
	var kind byte
	switch protocol {
	case "tunnellab/0.1":
		kind = 1
	case reverseALPN:
		kind = 2
	case udpALPN:
		kind = 3
	case probeALPN:
		kind = 4
	default:
		return nil, fmt.Errorf("unsupported protocol %q", protocol)
	}
	return append(append([]byte{}, protocolMagic...), kind), nil
}

func expectedProtocol(c Config) string {
	switch c.Mode {
	case "reverse-edge", "reverse-relay":
		return reverseALPN
	case "udp-edge", "udp-relay":
		return udpALPN
	default:
		return "tunnellab/0.1"
	}
}

func serverProtocol(conn *tls.Conn, c Config) (string, error) {
	if c.ProtocolNegotiation != "encrypted-preface" {
		p := conn.ConnectionState().NegotiatedProtocol
		if p != expectedProtocol(c) && p != probeALPN {
			return "", fmt.Errorf("ALPN mismatch: got %q", p)
		}
		return p, nil
	}
	if conn.ConnectionState().NegotiatedProtocol != "" {
		return "", fmt.Errorf("unexpected ALPN in encrypted-preface mode")
	}
	var header [6]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", fmt.Errorf("read encrypted preface: %w", err)
	}
	if !bytes.Equal(header[:5], protocolMagic) {
		return "", fmt.Errorf("invalid encrypted preface")
	}
	for _, p := range []string{expectedProtocol(c), probeALPN} {
		want, _ := protocolHeader(p)
		if bytes.Equal(header[:], want) {
			if err := writeAll(conn, want); err != nil {
				return "", fmt.Errorf("acknowledge encrypted preface: %w", err)
			}
			return p, nil
		}
	}
	return "", fmt.Errorf("encrypted preface protocol is not supported by this listener")
}

func dialTransport(ctx context.Context, c Config, tc *tls.Config, protocol string) (*tls.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	d := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", c.Peer)
	if err != nil {
		return nil, fmt.Errorf("TCP connect %s: %w", c.Peer, err)
	}
	clientConfig := tc.Clone()
	if c.ProtocolNegotiation == "encrypted-preface" {
		clientConfig.NextProtos = nil
	} else {
		clientConfig.NextProtos = []string{protocol}
	}
	conn := tls.Client(raw, clientConfig)
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, has := ctx.Deadline(); has {
		conn.SetDeadline(deadline)
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake %s: %w", c.Peer, err)
	}
	if c.ProtocolNegotiation == "encrypted-preface" {
		header, err := protocolHeader(protocol)
		if err != nil {
			return nil, err
		}
		if err := writeAll(conn, header); err != nil {
			return nil, fmt.Errorf("write encrypted preface: %w", err)
		}
		var ack [6]byte
		if _, err := io.ReadFull(conn, ack[:]); err != nil {
			return nil, fmt.Errorf("read encrypted preface acknowledgement: %w", err)
		}
		if !bytes.Equal(ack[:], header) {
			return nil, fmt.Errorf("encrypted preface acknowledgement mismatch")
		}
	} else if conn.ConnectionState().NegotiatedProtocol != protocol {
		return nil, fmt.Errorf("ALPN mismatch: expected %q", protocol)
	}
	conn.SetDeadline(time.Time{})
	ok = true
	return conn, nil
}

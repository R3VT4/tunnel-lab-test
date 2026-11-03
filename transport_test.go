package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

func TestEncryptedPrefaceEndToEnd(t *testing.T) {
	for _, mode := range []string{"direct", "reverse", "udp"} {
		t.Run(mode, func(t *testing.T) {
			e, r := testConfigs(t)
			e.ProtocolNegotiation, r.ProtocolNegotiation = "encrypted-preface", "encrypted-preface"
			var client Config
			switch mode {
			case "direct":
				r.Target = echoTarget(t, true).Addr().String()
				peer, _, _ := startEngine(t, r)
				e.Peer = peer
				edge, _, _ := startEngine(t, e)
				exchange(t, edge, bytes.Repeat([]byte("payload\x00"), 10000))
				client = e
			case "reverse":
				tunnel := listenLocal(t)
				edge, hub := startReverseEdge(t, e, tunnel)
				startReverseRelay(t, r, tunnel.Addr().String(), echoTarget(t, true).Addr().String())
				waitFor(t, func() bool { return hub.stats.controlConnected.Load() })
				exchange(t, edge, bytes.Repeat([]byte("reverse\x00"), 10000))
				client = r
				client.Mode, client.Peer, client.ServerName = "reverse-relay", tunnel.Addr().String(), "edge.tunnellab.local"
			case "udp":
				peer, _ := startUDPRelay(t, r, udpEcho(t).LocalAddr().String())
				edge, _ := startUDPEdge(t, e, peer)
				conn, err := net.Dial("udp", edge)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				for _, payload := range [][]byte{{}, bytes.Repeat([]byte{37}, maxDatagram)} {
					if _, err := conn.Write(payload); err != nil {
						t.Fatal(err)
					}
					buf := make([]byte, 65536)
					n, err := conn.Read(buf)
					if err != nil || !bytes.Equal(buf[:n], payload) {
						t.Fatalf("UDP mismatch: %v", err)
					}
				}
				client = e
				client.Mode, client.Peer = "udp-edge", peer
			}
			tc, err := tlsConfig(client)
			if err != nil {
				t.Fatal(err)
			}
			if len(tc.NextProtos) != 0 {
				t.Fatal("encrypted mode advertises ALPN")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			report, err := runProbe(ctx, client, tc, 65536, 3)
			if err != nil || report.BytesEachWay != 65536 {
				t.Fatalf("probe failed: %v", err)
			}
		})
	}
}

func TestEncryptedPrefaceRejectsInvalidAndCrossProtocolHeaders(t *testing.T) {
	e, r := testConfigs(t)
	e.ProtocolNegotiation, r.ProtocolNegotiation = "encrypted-preface", "encrypted-preface"
	peer, stats, _ := startEngine(t, r)
	tc, err := tlsConfig(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range [][]byte{[]byte("BAD!!!"), {'T', 'L', 'A', 'B', 1, 255}, {'T', 'L', 'A', 'B', 1, 2}, {'T', 'L'}} {
		conn, err := tls.Dial("tcp", peer, tc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(header); err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	waitFor(t, func() bool { return stats.errors.Load() == 4 })
}

func TestEncryptedPrefacePreservesCertificateVerification(t *testing.T) {
	e, r := testConfigs(t)
	e.ProtocolNegotiation, r.ProtocolNegotiation = "encrypted-preface", "encrypted-preface"
	e.Peer, _, _ = startEngine(t, r)
	for _, wrongCA := range []bool{false, true} {
		c := e
		if wrongCA {
			other, _ := testConfigs(t)
			c.CA = other.CA
		} else {
			c.ServerName = "wrong.example"
		}
		tc, err := tlsConfig(c)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := dialTransport(ctx, c, tc, probeALPN)
		cancel()
		if conn != nil {
			conn.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "TLS handshake") {
			t.Fatalf("certificate error missing: %v", err)
		}
	}
}

func TestTransportReportsTLSHandshakeTimeout(t *testing.T) {
	e, _ := testConfigs(t)
	e.ProtocolNegotiation = "encrypted-preface"
	ln := listenLocal(t)
	defer ln.Close()
	e.Peer = ln.Addr().String()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			buf := make([]byte, 4096)
			for {
				if _, err = c.Read(buf); err != nil {
					return
				}
			}
		}
	}()
	tc, err := tlsConfig(e)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = dialTransport(ctx, e, tc, probeALPN)
	if err == nil || !strings.Contains(err.Error(), "TLS handshake") {
		t.Fatalf("wrong phase: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out transport leaked socket")
	}
}

func TestNegotiationProfileMismatchFailsWithinDeadline(t *testing.T) {
	for _, clientPreface := range []bool{false, true} {
		t.Run(map[bool]string{false: "ALPN-client", true: "preface-client"}[clientPreface], func(t *testing.T) {
			e, r := testConfigs(t)
			if clientPreface {
				e.ProtocolNegotiation = "encrypted-preface"
			} else {
				r.ProtocolNegotiation = "encrypted-preface"
			}
			e.Peer, _, _ = startEngine(t, r)
			tc, err := tlsConfig(e)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := dialTransport(ctx, e, tc, probeALPN)
			if conn != nil {
				conn.Close()
			}
			if err == nil {
				t.Fatal("mismatched profiles accepted")
			}
		})
	}
}

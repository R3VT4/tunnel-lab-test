package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestCapacitySlotIsReusedAfterFailedHandshake(t *testing.T) {
	e, r := testConfigs(t)
	r.MaxConnections = 1
	peer, s, _ := startEngine(t, r)
	first, err := net.Dial("tcp", peer)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	waitFor(t, func() bool { return s.diagnostics.setupActive.Load() == 1 })
	second, err := net.Dial("tcp", peer)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	waitFor(t, func() bool { return s.rejected.Load() == 1 })
	first.Close()
	waitFor(t, func() bool { return s.active.Load() == 0 && s.diagnostics.setupActive.Load() == 0 })
	if s.diagnostics.setupFailures.Load() != 1 || s.diagnostics.peakActive.Load() != 1 {
		t.Fatal("handshake accounting incorrect")
	}
	e.Peer = peer
	tc, err := tlsConfig(e)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := runProbe(ctx, e, tc, 1024, 1); err != nil {
		t.Fatalf("released slot unusable: %v", err)
	}
	waitFor(t, func() bool { return s.active.Load() == 0 && s.diagnostics.probeActive.Load() == 0 })
	if s.errors.Load() != 1 || s.rejected.Load() != 1 {
		t.Fatal("healthy probe changed failure counts")
	}
}

func TestHalfCloseIsObservedWithoutLosingResponse(t *testing.T) {
	e, r := testConfigs(t)
	target := listenLocal(t)
	defer target.Close()
	received := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		payload, err := io.ReadAll(c)
		if err != nil {
			return
		}
		close(received)
		<-release
		c.Write(payload)
	}()
	r.Target = target.Addr().String()
	peer, _, _ := startEngine(t, r)
	e.Peer = peer
	addr, s, _ := startEngine(t, e)
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	want := bytes.Repeat([]byte("request after EOF\x00"), 100)
	if _, err := client.Write(want); err != nil {
		t.Fatal(err)
	}
	client.(*net.TCPConn).CloseWrite()
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("request EOF not propagated")
	}
	waitFor(t, func() bool { return s.diagnostics.halfClosedActive.Load() == 1 })
	if s.diagnostics.forwardingActive.Load() != 1 || s.diagnostics.setupActive.Load() != 0 {
		t.Fatal("wrong active phase")
	}
	once.Do(func() { close(release) })
	got, err := io.ReadAll(client)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("response lost after half-close: %v", err)
	}
	waitFor(t, func() bool {
		return s.active.Load() == 0 && s.diagnostics.halfClosedActive.Load() == 0 && s.diagnostics.forwardingActive.Load() == 0
	})
	if s.completed.Load() != 1 || s.errors.Load() != 0 {
		t.Fatal("normal transfer misclassified")
	}
}

func TestDirectIdleTimeoutHasSeparateCounter(t *testing.T) {
	e, r := testConfigs(t)
	r.IdleSeconds = 1
	r.Target = echoTarget(t, false).Addr().String()
	peer, s, _ := startEngine(t, r)
	e.Peer = peer
	tc, err := tlsConfig(e)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialTransport(ctx, e, tc, "tunnellab/0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitFor(t, func() bool { return s.diagnostics.forwardingActive.Load() == 1 })
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var b [1]byte
	_, err = conn.Read(b[:])
	if !errors.Is(err, io.EOF) {
		t.Fatalf("idle relay did not send TLS close_notify: %v", err)
	}
	waitFor(t, func() bool { return s.active.Load() == 0 })
	if s.diagnostics.idleTimeouts.Load() != 1 || s.errors.Load() != 0 || s.diagnostics.forwardingActive.Load() != 0 {
		t.Fatal("idle timeout counted as failure or leaked slot")
	}
}

func tcpConnPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln := listenLocal(t)
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := ln.Accept()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client.(*net.TCPConn), server.(*net.TCPConn)
}

func TestBridgeReportsResetAndShutdownSeparately(t *testing.T) {
	t.Run("reset", func(t *testing.T) {
		client, left := tcpConnPair(t)
		_, right := tcpConnPair(t)
		s := newStats()
		done := make(chan bridgeResult, 1)
		go func() { done <- bridgeReport(context.Background(), left, right, time.Second, s, true) }()
		client.SetLinger(0)
		client.Close()
		select {
		case result := <-done:
			if result.reason != "peer_disconnect" {
				t.Fatalf("wrong reset category: %+v", result)
			}
			s.transferFinished(result)
			if s.diagnostics.peerDisconnects.Load() != 1 || s.errors.Load() != 1 {
				t.Fatal("reset not counted")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("reset did not release bridge")
		}
	})
	t.Run("shutdown", func(t *testing.T) {
		_, left := tcpConnPair(t)
		_, right := tcpConnPair(t)
		ctx, cancel := context.WithCancel(context.Background())
		s := newStats()
		done := make(chan bridgeResult, 1)
		go func() { done <- bridgeReport(ctx, left, right, time.Second, s, true) }()
		cancel()
		select {
		case result := <-done:
			if result.reason != "canceled" {
				t.Fatalf("wrong shutdown category: %+v", result)
			}
			s.transferFinished(result)
			if s.errors.Load() != 0 || s.diagnostics.shutdownClosed.Load() != 1 {
				t.Fatal("shutdown counted as failure")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("shutdown leaked bridge")
		}
	})
}

func TestDiagnosticsEventsAreBoundedAndDoNotExposeRawErrors(t *testing.T) {
	s := newStats()
	for range 100 {
		s.setupFailed(context.Background(), "target_connect", errors.New("SECRET-ticket-and-key-material"))
	}
	s.setupFailed(context.Background(), "setup", atStage("tls_handshake", syscall.ECONNRESET))
	d := s.diagnostics.snapshot()
	if len(d["recent_events"].([]connectionEvent)) != 8 || d["last_error"].(*connectionEvent).Stage != "tls_handshake" {
		t.Fatal("history or stage incorrect")
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("raw error leaked into status")
	}
	before := s.errors.Load()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.setupFailed(ctx, "tls_handshake", ctx.Err())
	if s.errors.Load() != before {
		t.Fatal("shutdown counted as setup error")
	}
	request := httptest.NewRequest("GET", "http://127.0.0.1/api/status", nil)
	response := httptest.NewRecorder()
	adminHandler(Config{Mode: "edge", MaxConnections: 256, IdleSeconds: 120}, s).ServeHTTP(response, request)
	var status map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status["max_connections"] != float64(256) || status["connection_diagnostics"] == nil {
		t.Fatal("status lacks capacity or diagnostics")
	}
	if _, ok := s.snapshot("udp-edge")["connection_diagnostics"]; ok {
		t.Fatal("unsupported-mode diagnostics presented as instrumented")
	}
}

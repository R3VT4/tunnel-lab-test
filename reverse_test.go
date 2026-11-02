package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func startReverseEdge(t *testing.T, e Config, tunnel net.Listener) (string, *reverseHub) {
	t.Helper()
	e.Mode = "reverse-edge"
	e.Peer = ""
	e.ServerName = ""
	tc, err := tlsConfig(e)
	if err != nil {
		t.Fatal(err)
	}
	users := listenLocal(t)
	ctx, cancel := context.WithCancel(context.Background())
	s := newStats()
	hub := newHub(s)
	done := make(chan error, 1)
	go func() { done <- hub.serve(ctx, users, tunnel, e, tc) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("reverse edge shutdown hung")
		}
	})
	return users.Addr().String(), hub
}
func startReverseRelay(t *testing.T, r Config, peer, target string) (*Stats, context.CancelFunc) {
	t.Helper()
	r.Mode = "reverse-relay"
	r.Peer = peer
	r.Target = target
	r.Listen = ""
	r.ServerName = "edge.tunnellab.local"
	tc, err := tlsConfig(r)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := newStats()
	done := make(chan error, 1)
	go func() { done <- serveReverseRelay(ctx, r, tc, s) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("reverse relay shutdown hung")
		}
	})
	return s, cancel
}
func echoTarget(t *testing.T, waitEOF bool) net.Listener {
	t.Helper()
	ln := listenLocal(t)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(8 * time.Second))
				if waitEOF {
					b, err := io.ReadAll(c)
					if err == nil {
						c.Write(b)
					}
				} else {
					io.Copy(c, c)
				}
			}()
		}
	}()
	return ln
}
func exchange(t *testing.T, addr string, payload []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Error(err)
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write(payload); err != nil {
		t.Error(err)
		return
	}
	conn.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Error(err)
		return
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch: got %d, want %d", len(got), len(payload))
	}
}

func TestReverseConcurrentTransfersAndHalfClose(t *testing.T) {
	e, r := testConfigs(t)
	tunnel := listenLocal(t)
	addr, hub := startReverseEdge(t, e, tunnel)
	target := echoTarget(t, true)
	rs, _ := startReverseRelay(t, r, tunnel.Addr().String(), target.Addr().String())
	waitFor(t, func() bool { return rs.controlConnected.Load() && hub.stats.controlConnected.Load() })
	payload := bytes.Repeat([]byte("\x00reverse\xff"), 50000)
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() { exchange(t, addr, payload) })
	}
	wg.Wait()
	waitFor(t, func() bool { return hub.stats.active.Load() == 0 && rs.active.Load() == 0 })
	for _, s := range []*Stats{hub.stats, rs} {
		if s.errors.Load() != 0 {
			t.Errorf("unexpected errors %d", s.errors.Load())
		}
		if s.forwarded.Load() != int64(6*len(payload)) || s.returned.Load() != int64(6*len(payload)) {
			t.Errorf("incorrect counters: %v", s.snapshot("test"))
		}
	}
}

func TestControlReconnectPreservesEstablishedData(t *testing.T) {
	e, r := testConfigs(t)
	tunnel := listenLocal(t)
	addr, hub := startReverseEdge(t, e, tunnel)
	target := echoTarget(t, false)
	rs, _ := startReverseRelay(t, r, tunnel.Addr().String(), target.Addr().String())
	waitFor(t, func() bool { return rs.controlConnected.Load() })
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	roundtrip := func(text string) {
		t.Helper()
		if _, err := conn.Write([]byte(text)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(text))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != text {
			t.Fatal("data changed")
		}
	}
	roundtrip("before control loss")
	hub.mu.Lock()
	previous := hub.control
	hub.mu.Unlock()
	if previous == nil {
		t.Fatal("missing control session")
	}
	previous.close()
	roundtrip("during control loss")
	waitFor(t, func() bool {
		hub.mu.Lock()
		defer hub.mu.Unlock()
		return hub.control != nil && hub.control != previous && rs.controlConnected.Load()
	})
	roundtrip("after control recovery")
	newConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer newConn.Close()
	newConn.SetDeadline(time.Now().Add(time.Second))
	newConn.Write([]byte("new"))
	buf := make([]byte, 3)
	if _, err := io.ReadFull(newConn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "new" {
		t.Fatal("new connection failed")
	}
	if rs.controlReconnects.Load() < 1 {
		t.Fatal("reconnect not counted")
	}
}

func TestRelayRetriesWhenEdgeStartsLater(t *testing.T) {
	e, r := testConfigs(t)
	reserve := listenLocal(t)
	address := reserve.Addr().String()
	reserve.Close()
	target := echoTarget(t, true)
	rs, _ := startReverseRelay(t, r, address, target.Addr().String())
	waitFor(t, func() bool { return rs.controlReconnects.Load() > 0 })
	ln, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := startReverseEdge(t, e, ln)
	waitFor(t, func() bool { return rs.controlConnected.Load() })
	exchange(t, addr, []byte("edge came online"))
}

func TestReverseUnknownAndReplayedTicketsRejected(t *testing.T) {
	e, r := testConfigs(t)
	tunnel := listenLocal(t)
	addr, hub := startReverseEdge(t, e, tunnel)
	r.Mode = "reverse-relay"
	r.Peer = tunnel.Addr().String()
	r.ServerName = "edge.tunnellab.local"
	tc, err := tlsConfig(r)
	if err != nil {
		t.Fatal(err)
	}
	dial := func() net.Conn {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		c, err := dialReverse(ctx, r, tc)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		t.Cleanup(func() { c.Close() })
		return c
	}
	unknown := dial()
	writeFrame(unknown, controlFrame{Type: "data", Ticket: string(bytes.Repeat([]byte("0"), 64))})
	if f, err := readFrame(unknown); err == nil {
		t.Fatalf("unknown ticket accepted: %+v", f)
	}
	control := dial()
	writeFrame(control, controlFrame{Type: "control"})
	f, err := readFrame(control)
	if err != nil || f.Type != "ready" {
		t.Fatal("control not ready", err)
	}
	user, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer user.Close()
	user.SetDeadline(time.Now().Add(2 * time.Second))
	user.Write([]byte("first"))
	open, err := readFrame(control)
	if err != nil || open.Type != "open" {
		t.Fatal("missing open", err)
	}
	data := dial()
	writeFrame(data, controlFrame{Type: "data", Ticket: open.Ticket})
	f, err = readFrame(data)
	if err != nil || f.Type != "ready" {
		t.Fatal("data not ready", err)
	}
	buf := make([]byte, 5)
	if _, err = io.ReadFull(data, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "first" {
		t.Fatal("incorrect stream")
	}
	replay := dial()
	writeFrame(replay, controlFrame{Type: "data", Ticket: open.Ticket})
	if _, err = readFrame(replay); err == nil {
		t.Fatal("replayed ticket accepted")
	}
	data.Write([]byte("reply"))
	if _, err = io.ReadFull(user, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "reply" {
		t.Fatal("live stream damaged by replay")
	}
	waitFor(t, func() bool { return hub.stats.pending.Load() == 0 })
}

func TestReverseRejectsWrongRoleAndDuplicateControl(t *testing.T) {
	e, r := testConfigs(t)
	tunnel := listenLocal(t)
	_, _ = startReverseEdge(t, e, tunnel)
	for _, cfg := range []Config{e, r} {
		cfg.Mode = "reverse-relay"
		cfg.Peer = tunnel.Addr().String()
		cfg.ServerName = "edge.tunnellab.local"
		tc, err := tlsConfig(cfg)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := dialReverse(ctx, cfg, tc)
		cancel()
		if cfg.Cert == e.Cert {
			if err == nil {
				conn.SetDeadline(time.Now().Add(time.Second))
				writeFrame(conn, controlFrame{Type: "control"})
				_, err = readFrame(conn)
				conn.Close()
			}
			if err == nil {
				t.Fatal("edge credential accepted as relay")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		writeFrame(conn, controlFrame{Type: "control"})
		f, err := readFrame(conn)
		if err != nil || f.Type != "ready" {
			t.Fatal("valid control rejected", err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		duplicate, err := dialReverse(ctx, cfg, tc)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		defer duplicate.Close()
		duplicate.SetDeadline(time.Now().Add(time.Second))
		writeFrame(duplicate, controlFrame{Type: "control"})
		f, err = readFrame(duplicate)
		if err != nil || f.Type != "busy" {
			t.Fatal("duplicate control not refused", err)
		}
	}
}

func TestControlFramingRejectsOversizeAndPreservesFollowingBytes(t *testing.T) {
	var b bytes.Buffer
	writeFrame(&b, controlFrame{Type: "ready"})
	b.WriteString("payload")
	if _, err := readFrame(&b); err != nil {
		t.Fatal(err)
	}
	if b.String() != "payload" {
		t.Fatal("frame parser consumed data bytes")
	}
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], 513)
	if _, err := readFrame(bytes.NewReader(h[:])); err == nil {
		t.Fatal("oversize frame accepted")
	}
}

func TestReversePendingBoundAndCleanupOnControlLoss(t *testing.T) {
	e, r := testConfigs(t)
	e.MaxConnections = 1
	tunnel := listenLocal(t)
	addr, hub := startReverseEdge(t, e, tunnel)
	r.Mode = "reverse-relay"
	r.Peer = tunnel.Addr().String()
	r.ServerName = "edge.tunnellab.local"
	tc, err := tlsConfig(r)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	control, err := dialReverse(ctx, r, tc)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	control.SetDeadline(time.Now().Add(2 * time.Second))
	writeFrame(control, controlFrame{Type: "control"})
	if _, err := readFrame(control); err != nil {
		t.Fatal(err)
	}
	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if f, err := readFrame(control); err != nil || f.Type != "open" {
		t.Fatal("missing request", err)
	}
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("over-limit connection stayed open")
	}
	if hub.stats.pending.Load() != 1 {
		t.Fatal("incorrect pending count")
	}
	waitFor(t, func() bool { return hub.stats.rejected.Load() == 1 })
	control.Close()
	waitFor(t, func() bool { return hub.stats.pending.Load() == 0 && hub.stats.active.Load() == 0 })
	hub.mu.Lock()
	defer hub.mu.Unlock()
	if len(hub.pending) != 0 {
		t.Fatal("pending request leaked")
	}
}

func TestControlHeartbeatKeepsIdleSessionAlive(t *testing.T) {
	e, r := testConfigs(t)
	tunnel := listenLocal(t)
	_, hub := startReverseEdge(t, e, tunnel)
	target := echoTarget(t, true)
	rs, _ := startReverseRelay(t, r, tunnel.Addr().String(), target.Addr().String())
	waitFor(t, func() bool { return rs.controlConnected.Load() && hub.stats.controlConnected.Load() })
	hub.mu.Lock()
	original := hub.control
	hub.mu.Unlock()
	// Exceed the 15s control read deadline: ping/pong must keep this same session alive.
	timer := time.NewTimer(16 * time.Second)
	defer timer.Stop()
	<-timer.C
	hub.mu.Lock()
	same := hub.control == original
	hub.mu.Unlock()
	if !same || !rs.controlConnected.Load() || rs.controlReconnects.Load() != 0 {
		t.Fatal("healthy idle control session was lost")
	}
}

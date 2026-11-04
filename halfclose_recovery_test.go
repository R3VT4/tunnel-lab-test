package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

type notifiedHalfCloseConn struct {
	net.Conn
	called            chan struct{}
	readErrAfterClose error
}

func (c *notifiedHalfCloseConn) CloseWrite() error {
	close(c.called)
	return syscall.ENOTCONN
}

func (c *notifiedHalfCloseConn) Read(p []byte) (int, error) {
	if c.readErrAfterClose != nil {
		<-c.called
		return 0, c.readErrAfterClose
	}
	return c.Conn.Read(p)
}

// Model request EOF while the target's send side is already closed, but its
// response direction has not finished. The response must still be drained.
func TestNotConnectedHalfClosePreservesDelayedResponse(t *testing.T) {
	left, client := net.Pipe()
	right, target := net.Pipe()
	defer client.Close()
	defer target.Close()
	defer left.Close()
	defer right.Close()
	called := make(chan struct{})
	s := newStats()
	done := make(chan bridgeResult, 1)
	go func() {
		result := bridgeReportSides(context.Background(), &faultBridgeConn{Conn: left, readErr: io.EOF}, &notifiedHalfCloseConn{Conn: right, called: called}, time.Second, s, true, "tunnel", "target")
		left.Close()
		right.Close()
		done <- result
	}()
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("CloseWrite not reached")
	}
	select {
	case result := <-done:
		t.Fatalf("bridge closed response direction early: %+v", result)
	case <-time.After(30 * time.Millisecond):
	}
	want := bytes.Repeat([]byte("delayed binary response\x00\xff"), 4096)
	writeDone := make(chan error, 1)
	go func() { _, err := target.Write(want); target.Close(); writeDone <- err }()
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(client)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("response lost: bytes=%d/%d err=%v", len(got), len(want), err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.reason != "eof" {
			t.Fatalf("unexpected end: %+v", result)
		}
		s.transferFinished(result)
	case <-time.After(time.Second):
		t.Fatal("bridge leaked after target EOF")
	}
	if s.returned.Load() != int64(len(want)) || s.errors.Load() != 0 || s.completed.Load() != 1 || s.diagnostics.halfClosedActive.Load() != 0 {
		t.Fatal("byte/lifecycle accounting incorrect")
	}
	if s.diagnostics.snapshot()["half_close_already_closed"] != int64(1) {
		t.Fatal("recovered half-close not observable")
	}
}

func TestNotConnectedHalfCloseKeepsLifecycleBounds(t *testing.T) {
	for _, scenario := range []string{"idle", "cancel", "reset", "legacy"} {
		t.Run(scenario, func(t *testing.T) {
			left, client := net.Pipe()
			right, target := net.Pipe()
			defer left.Close()
			defer right.Close()
			defer client.Close()
			defer target.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			called := make(chan struct{})
			conn := &notifiedHalfCloseConn{Conn: right, called: called}
			idle := time.Second
			if scenario == "idle" {
				idle = 50 * time.Millisecond
			}
			if scenario == "reset" {
				conn.readErrAfterClose = syscall.ECONNRESET
			}
			s := newStats()
			done := make(chan bridgeResult, 1)
			go func() {
				done <- bridgeReportSides(ctx, &faultBridgeConn{Conn: left, readErr: io.EOF}, conn, idle, s, scenario != "legacy", "tunnel", "target")
			}()
			select {
			case <-called:
			case <-time.After(time.Second):
				t.Fatal("close not reached")
			}
			if scenario == "cancel" {
				cancel()
			}
			var result bridgeResult
			select {
			case result = <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("bridge leaked")
			}
			want := map[string]string{"idle": "timeout", "cancel": "canceled", "reset": "peer_disconnect", "legacy": "io_error"}[scenario]
			if result.reason != want {
				t.Fatalf("wrong outcome: %+v", result)
			}
			s.transferFinished(result)
			if s.diagnostics.halfClosedActive.Load() != 0 {
				t.Fatal("half-close gauge leaked")
			}
			if scenario == "legacy" {
				if s.diagnostics.halfCloseAlreadyClosed.Load() != 0 || s.errors.Load() != 1 {
					t.Fatal("legacy bridge behavior changed")
				}
			} else if s.diagnostics.halfCloseAlreadyClosed.Load() != 1 {
				t.Fatal("recovery not counted")
			}
			if scenario == "reset" && s.diagnostics.peerDisconnects.Load() != 1 {
				t.Fatal("real reset hidden")
			}
			if scenario == "idle" && (s.errors.Load() != 0 || s.diagnostics.idleTimeouts.Load() != 1) {
				t.Fatal("idle outcome wrong")
			}
			if scenario == "cancel" && (s.errors.Load() != 0 || s.diagnostics.shutdownClosed.Load() != 1) {
				t.Fatal("shutdown outcome wrong")
			}
		})
	}
}

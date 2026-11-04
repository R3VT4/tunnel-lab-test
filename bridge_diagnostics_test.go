package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type faultBridgeConn struct {
	net.Conn
	readErr, writeErr, closeWriteErr error
	payload                          []byte
	once                             sync.Once
	shortWrite                       bool
}

func (c *faultBridgeConn) Read(p []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	n := 0
	c.once.Do(func() { n = copy(p, c.payload) })
	if n > 0 {
		return n, nil
	}
	return c.Conn.Read(p)
}
func (c *faultBridgeConn) Write(p []byte) (int, error) {
	if c.shortWrite {
		return len(p) - 1, nil
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Conn.Write(p)
}
func (c *faultBridgeConn) CloseWrite() error { return c.closeWriteErr }

func TestBridgePinpointsReadWriteAndCloseWrite(t *testing.T) {
	for _, side := range []string{"tunnel", "target"} {
		for _, operation := range []string{"read", "write", "close_write"} {
			t.Run(side+"/"+operation, func(t *testing.T) {
				left, leftPeer := net.Pipe()
				right, rightPeer := net.Pipe()
				defer left.Close()
				defer right.Close()
				defer leftPeer.Close()
				defer rightPeer.Close()
				l, r := &faultBridgeConn{Conn: left}, &faultBridgeConn{Conn: right}
				broken, source := l, r
				if side == "target" {
					broken, source = r, l
				}
				switch operation {
				case "read":
					broken.readErr = syscall.ENOTCONN
				case "write":
					broken.writeErr = syscall.ENOTCONN
					source.payload = []byte("secret payload")
				case "close_write":
					source.readErr = io.EOF
					broken.closeWriteErr = syscall.EBADF
				}
				wantErr, wantCode := error(syscall.ENOTCONN), "not_connected"
				if operation == "close_write" {
					wantErr, wantCode = syscall.EBADF, "bad_file_descriptor"
				}
				s := newStats()
				result := bridgeReportSides(context.Background(), l, r, time.Second, s, true, "tunnel", "target")
				if result.reason != "io_error" || !errors.Is(result.err, wantErr) {
					t.Fatalf("primary failure lost: %+v", result)
				}
				s.transferFinished(result)
				d := s.diagnostics.snapshot()
				event := d["last_error"].(*connectionEvent)
				if event.Side != side || event.Operation != operation || event.ErrorCode != wantCode {
					t.Fatalf("wrong attribution: %+v", event)
				}
				if d["transfer_failure_counts"].(map[string]int64)[side+"."+operation+"."+wantCode] != 1 || s.diagnostics.transferFailures.Load() != 1 {
					t.Fatal("failure totals disagree")
				}
				if s.diagnostics.halfClosedActive.Load() != 0 {
					t.Fatal("half-close gauge leaked")
				}
				b, _ := json.Marshal(d)
				if strings.Contains(string(b), "secret payload") {
					t.Fatal("payload exposed")
				}
			})
		}
	}
}

func TestBridgeErrorCodesAndSafeFallback(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{syscall.ENOTCONN, "not_connected"}, {syscall.EBADF, "bad_file_descriptor"},
		{syscall.ESHUTDOWN, "socket_shutdown"}, {syscall.ECONNABORTED, "connection_aborted"},
		{syscall.ECONNRESET, "connection_reset"}, {syscall.EPIPE, "broken_pipe"},
		{net.ErrClosed, "net_closed"}, {io.ErrClosedPipe, "closed_pipe"},
		{io.ErrShortWrite, "short_write"}, {io.ErrUnexpectedEOF, "unexpected_eof"},
		{errors.New("SECRET raw address token"), "io_error"},
	} {
		s := newStats()
		err := atBridgeIO("untrusted side", "untrusted operation", &net.OpError{Op: "SECRET", Err: tc.err})
		s.transferFinished(bridgeResult{reason: errorKind(err), err: err})
		d := s.diagnostics.snapshot()
		event := d["last_error"].(*connectionEvent)
		if event.ErrorCode != tc.code || event.Side != "unknown" || event.Operation != "unknown" {
			t.Fatalf("bad safe classification: %+v", event)
		}
		b, _ := json.Marshal(d)
		if strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "untrusted") {
			t.Fatal("raw metadata exposed")
		}
		// Snapshot maps are independent copies, not the mutable internal map.
		d["transfer_failure_counts"].(map[string]int64)["injected"] = 99
		if _, exists := s.diagnostics.snapshot()["transfer_failure_counts"].(map[string]int64)["injected"]; exists {
			t.Fatal("snapshot aliases state")
		}
	}
}

func TestActivityConnPreservesEOFAndErrorUnwrap(t *testing.T) {
	left, peer := net.Pipe()
	defer left.Close()
	defer peer.Close()
	var count atomic.Int64
	c := activityConn{Conn: &faultBridgeConn{Conn: left, readErr: io.EOF}, touch: func() {}, counter: &count, side: "client"}
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("clean EOF wrapped: %v", err)
	}
	c.Conn = &faultBridgeConn{Conn: left, writeErr: syscall.EPIPE}
	_, err := c.Write([]byte("payload"))
	var detail *bridgeIOError
	if !errors.Is(err, syscall.EPIPE) || !errors.As(err, &detail) || detail.side != "client" || detail.operation != "write" {
		t.Fatalf("write annotation lost: %v", err)
	}
	c.Conn = &faultBridgeConn{Conn: left, shortWrite: true}
	n, err := c.Write([]byte("payload"))
	if n != 6 || count.Load() != 6 || !errors.Is(err, io.ErrShortWrite) || !errors.As(err, &detail) || detail.operation != "write" {
		t.Fatalf("short write attribution or byte accounting lost: n=%d, err=%v", n, err)
	}
}

package main

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Stats struct {
	diagnostics        connectionDiagnostics
	active             atomic.Int64
	accepted           atomic.Int64
	rejected           atomic.Int64
	errors             atomic.Int64
	completed          atomic.Int64
	forwarded          atomic.Int64
	returned           atomic.Int64
	controlConnected   atomic.Bool
	controlReconnects  atomic.Int64
	pending            atomic.Int64
	datagramsForwarded atomic.Int64
	datagramsReturned  atomic.Int64
	dropped            atomic.Int64
	probes             atomic.Int64
	started            time.Time
}

func newStats() *Stats { return &Stats{started: time.Now()} }
func (s *Stats) snapshot(mode string) map[string]any {
	out := map[string]any{"version": version, "mode": mode, "uptime_seconds": int(time.Since(s.started).Seconds()), "active": s.active.Load(), "accepted": s.accepted.Load(), "rejected": s.rejected.Load(), "errors": s.errors.Load(), "completed": s.completed.Load(), "forwarded_bytes": s.forwarded.Load(), "returned_bytes": s.returned.Load(), "control_connected": s.controlConnected.Load(), "control_reconnects": s.controlReconnects.Load(), "pending": s.pending.Load(), "datagrams_forwarded": s.datagramsForwarded.Load(), "datagrams_returned": s.datagramsReturned.Load(), "local_datagram_drops": s.dropped.Load(), "probe_runs": s.probes.Load()}
	if mode == "edge" || mode == "relay" {
		out["connection_diagnostics"] = s.diagnostics.snapshot()
	}
	return out
}

// Each accepted connection gets a separate TLS connection. There is no shared
// multiplexing queue, application-level retransmission, or connection migration.
func serve(ctx context.Context, listener net.Listener, c Config, tc *tls.Config, s *Stats) error {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	sem := make(chan struct{}, c.MaxConnections)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	for {
		incoming, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.accepted.Add(1)
		select {
		case sem <- struct{}{}:
		default:
			s.rejected.Add(1)
			s.diagnostics.event("capacity", "limit_reached", false)
			incoming.Close()
			continue
		}
		wg.Add(1)
		s.diagnostics.noteActive(s.active.Add(1))
		s.diagnostics.setupActive.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem; s.active.Add(-1) }()
			defer incoming.Close()
			forwardingOpen, probeOpen := false, false
			// Keep the phase visible until deferred TLS/socket cleanup ends.
			defer func() {
				if forwardingOpen {
					s.diagnostics.forwardingActive.Add(-1)
				}
				if probeOpen {
					s.diagnostics.probeActive.Add(-1)
				}
			}()
			setupOpen := true
			setupDone := func() {
				if setupOpen {
					s.diagnostics.setupActive.Add(-1)
					setupOpen = false
				}
			}
			defer setupDone()
			stopIncoming := context.AfterFunc(ctx, func() { incoming.Close() })
			defer stopIncoming()
			left := incoming
			setupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if c.Mode == "relay" {
				t := tls.Server(incoming, tc)
				defer t.Close()
				t.SetDeadline(time.Now().Add(setupTimeout))
				if err := t.HandshakeContext(setupCtx); err != nil {
					s.setupFailed(ctx, "tls_handshake", err)
					log.Printf("TLS handshake from %s: %v", incoming.RemoteAddr(), err)
					return
				}
				protocol, err := serverProtocol(t, c)
				if err != nil {
					s.setupFailed(ctx, "protocol_negotiation", err)
					log.Printf("protocol negotiation from %s: %v", incoming.RemoteAddr(), err)
					return
				}
				if protocol == probeALPN {
					setupDone()
					s.diagnostics.probeActive.Add(1)
					probeOpen = true
					cancel()
					s.probes.Add(1)
					if err := handleProbe(ctx, t); err != nil && ctx.Err() == nil {
						s.errors.Add(1)
						s.diagnostics.probeFailures.Add(1)
						s.diagnostics.event("probe", errorKind(err), true)
					}
					return
				}
				if protocol != "tunnellab/0.1" {
					s.setupFailed(ctx, "protocol_negotiation", io.ErrUnexpectedEOF)
					return
				}
				t.SetDeadline(time.Time{})
				left = t
			}
			var right net.Conn
			var dialErr error
			dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
			if c.Mode == "edge" {
				right, dialErr = dialTransport(setupCtx, c, tc, "tunnellab/0.1")
			} else {
				right, dialErr = dialer.DialContext(setupCtx, "tcp", c.Target)
			}
			if dialErr != nil {
				s.setupFailed(ctx, "target_connect", dialErr)
				log.Print("connection setup failed: ", dialErr)
				return
			}
			defer right.Close()
			if t, ok := right.(*tls.Conn); ok && c.ProtocolNegotiation != "encrypted-preface" && t.ConnectionState().NegotiatedProtocol != "tunnellab/0.1" {
				s.setupFailed(ctx, "protocol_negotiation", io.ErrUnexpectedEOF)
				return
			}
			cancel()
			setupDone()
			s.diagnostics.forwardingActive.Add(1)
			forwardingOpen = true
			s.transferFinished(bridgeReport(ctx, left, right, time.Duration(c.IdleSeconds)*time.Second, s, true))
		}()
	}
}

// A shared idle deadline is refreshed by activity in either direction. An EOF
// half-closes the destination, allowing request-EOF-response protocols to work.
type activityConn struct {
	net.Conn
	touch   func()
	counter *atomic.Int64
}

func (c activityConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, e
}
func (c activityConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	if n > 0 {
		c.counter.Add(int64(n))
		c.touch()
	}
	return n, e
}

func bridge(ctx context.Context, left, right net.Conn, idle time.Duration, s *Stats) bool {
	return bridgeReport(ctx, left, right, idle, s, false).reason == "eof"
}

func bridgeReport(ctx context.Context, left, right net.Conn, idle time.Duration, s *Stats, observe bool) bridgeResult {
	closeBoth := func() { left.Close(); right.Close() }
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	var deadlineMu sync.Mutex
	touch := func() {
		deadlineMu.Lock()
		defer deadlineMu.Unlock()
		deadline := time.Now().Add(idle)
		left.SetDeadline(deadline)
		right.SetDeadline(deadline)
	}
	touch()
	l := activityConn{left, touch, &s.returned}
	r := activityConn{right, touch, &s.forwarded}
	results := make(chan error, 2)
	var halfOnce sync.Once
	halfClosed := false
	defer func() {
		if halfClosed {
			s.diagnostics.halfClosedActive.Add(-1)
		}
	}()
	copyOne := func(dst, src activityConn) {
		_, err := io.CopyBuffer(dst, src, make([]byte, 32*1024))
		if err == nil {
			if cw, ok := dst.Conn.(interface{ CloseWrite() error }); ok {
				err = cw.CloseWrite()
			}
			if observe && err == nil {
				halfOnce.Do(func() { halfClosed = true; s.diagnostics.halfClosedActive.Add(1) })
			}
		}
		results <- err
	}
	go copyOne(r, l)
	go copyOne(l, r)
	err1 := <-results
	if err1 != nil {
		closeBoth()
	}
	err2 := <-results
	if ctx.Err() != nil {
		return bridgeResult{reason: "canceled", err: ctx.Err()}
	}
	root := err1
	if root == nil {
		root = err2
	}
	if root == nil {
		return bridgeResult{reason: "eof"}
	}
	return bridgeResult{reason: errorKind(root), err: root}
}

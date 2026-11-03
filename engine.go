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
	return map[string]any{"version": version, "mode": mode, "uptime_seconds": int(time.Since(s.started).Seconds()), "active": s.active.Load(), "accepted": s.accepted.Load(), "rejected": s.rejected.Load(), "errors": s.errors.Load(), "completed": s.completed.Load(), "forwarded_bytes": s.forwarded.Load(), "returned_bytes": s.returned.Load(), "control_connected": s.controlConnected.Load(), "control_reconnects": s.controlReconnects.Load(), "pending": s.pending.Load(), "datagrams_forwarded": s.datagramsForwarded.Load(), "datagrams_returned": s.datagramsReturned.Load(), "local_datagram_drops": s.dropped.Load(), "probe_runs": s.probes.Load()}
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
			incoming.Close()
			continue
		}
		wg.Add(1)
		s.active.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem; s.active.Add(-1) }()
			defer incoming.Close()
			stopIncoming := context.AfterFunc(ctx, func() { incoming.Close() })
			defer stopIncoming()
			left := incoming
			setupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if c.Mode == "relay" {
				t := tls.Server(incoming, tc)
				t.SetDeadline(time.Now().Add(setupTimeout))
				if err := t.HandshakeContext(setupCtx); err != nil {
					s.errors.Add(1)
					log.Printf("TLS handshake from %s: %v", incoming.RemoteAddr(), err)
					return
				}
				protocol, err := serverProtocol(t, c)
				if err != nil {
					s.errors.Add(1)
					log.Printf("protocol negotiation from %s: %v", incoming.RemoteAddr(), err)
					return
				}
				if protocol == probeALPN {
					cancel()
					s.probes.Add(1)
					if err := handleProbe(ctx, t); err != nil && ctx.Err() == nil {
						s.errors.Add(1)
					}
					return
				}
				if protocol != "tunnellab/0.1" {
					s.errors.Add(1)
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
				s.errors.Add(1)
				log.Print("connection setup failed: ", dialErr)
				return
			}
			defer right.Close()
			if t, ok := right.(*tls.Conn); ok && c.ProtocolNegotiation != "encrypted-preface" && t.ConnectionState().NegotiatedProtocol != "tunnellab/0.1" {
				s.errors.Add(1)
				return
			}
			cancel()
			if bridge(ctx, left, right, time.Duration(c.IdleSeconds)*time.Second, s) {
				s.completed.Add(1)
			} else if ctx.Err() == nil {
				s.errors.Add(1)
			}
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
	closeBoth := func() { left.Close(); right.Close() }
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	touch := func() { deadline := time.Now().Add(idle); left.SetDeadline(deadline); right.SetDeadline(deadline) }
	touch()
	l := activityConn{left, touch, &s.returned}
	r := activityConn{right, touch, &s.forwarded}
	results := make(chan error, 2)
	copyOne := func(dst, src activityConn) {
		_, err := io.CopyBuffer(dst, src, make([]byte, 32*1024))
		if err == nil {
			if cw, ok := dst.Conn.(interface{ CloseWrite() error }); ok {
				err = cw.CloseWrite()
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
	return err1 == nil && err2 == nil
}

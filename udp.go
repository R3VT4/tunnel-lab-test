package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const udpALPN = "tunnellab-udp-over-tls/0.3"
const maxDatagram = 65507
const maxQueuedBytes = 256 * 1024

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
func writeDatagram(w io.Writer, p []byte) error {
	if len(p) > maxDatagram {
		return errors.New("datagram too large")
	}
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(p)))
	if err := writeAll(w, h[:]); err != nil {
		return err
	}
	return writeAll(w, p)
}
func readDatagram(r io.Reader, buffer []byte) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n > maxDatagram || n > len(buffer) {
		return nil, errors.New("invalid datagram length")
	}
	_, err := io.ReadFull(r, buffer[:n])
	return buffer[:n], err
}
func normalSessionEnd(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

type udpFlow struct {
	ctx    context.Context
	cancel context.CancelFunc
	queue  chan []byte
	queued atomic.Int64
	mu     sync.Mutex
	closed bool
}

func (f *udpFlow) enqueue(packet []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.ctx.Err() != nil || f.queued.Load()+int64(len(packet)) > maxQueuedBytes {
		return false
	}
	// Single producer, with a separate byte budget as well as a packet cap.
	if len(f.queue) == cap(f.queue) {
		return false
	}
	p := append([]byte{}, packet...)
	f.queued.Add(int64(len(p)))
	select {
	case f.queue <- p:
		return true
	default:
		f.queued.Add(-int64(len(p)))
		return false
	}
}
func (f *udpFlow) discard(s *Stats) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	for {
		select {
		case p := <-f.queue:
			f.queued.Add(-int64(len(p)))
			s.dropped.Add(1)
		default:
			return
		}
	}
}

// UDP source address+port maps to one independently authenticated TLS stream.
// Framing preserves datagram boundaries, including empty datagrams. This is
// UDP-over-TCP/TLS, NOT native UDP transport: TCP head-of-line blocking applies.
func serveUDPEdge(ctx context.Context, udp *net.UDPConn, c Config, tc *tls.Config, s *Stats) error {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { udp.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer func() { cancel(); udp.Close(); wg.Wait() }()
	var mu sync.Mutex
	flows := make(map[string]*udpFlow)
	depth := c.UDPQueuePackets
	if depth == 0 {
		depth = 8
	}
	buffer := make([]byte, 65536)
	for {
		n, source, err := udp.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if n > maxDatagram {
			s.dropped.Add(1)
			continue
		}
		key := source.String()
		mu.Lock()
		flow := flows[key]
		if flow == nil {
			if len(flows) >= c.MaxConnections {
				mu.Unlock()
				s.rejected.Add(1)
				s.dropped.Add(1)
				continue
			}
			flowCtx, flowCancel := context.WithCancel(ctx)
			flow = &udpFlow{ctx: flowCtx, cancel: flowCancel, queue: make(chan []byte, depth)}
			flows[key] = flow
			s.accepted.Add(1)
			s.active.Add(1)
			wg.Add(1)
			go func(f *udpFlow, source *net.UDPAddr, key string) {
				defer wg.Done()
				err := f.run(udp, source, c, tc, s)
				f.cancel()
				f.discard(s)
				mu.Lock()
				if flows[key] == f {
					delete(flows, key)
				}
				mu.Unlock()
				s.active.Add(-1)
				if normalSessionEnd(err) || ctx.Err() != nil {
					s.completed.Add(1)
				} else {
					s.errors.Add(1)
				}
			}(flow, source, key)
		}
		mu.Unlock()
		if !flow.enqueue(buffer[:n]) {
			s.dropped.Add(1)
		}
	}
}

func (f *udpFlow) run(udp *net.UDPConn, source *net.UDPAddr, c Config, tc *tls.Config, s *Stats) error {
	setupCtx, cancel := context.WithTimeout(f.ctx, setupTimeout)
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}, Config: tc}
	conn, err := d.DialContext(setupCtx, "tcp", c.Peer)
	cancel()
	if err != nil {
		return err
	}
	defer conn.Close()
	if conn.(*tls.Conn).ConnectionState().NegotiatedProtocol != udpALPN {
		return errors.New("UDP ALPN mismatch")
	}
	stop := context.AfterFunc(f.ctx, func() { conn.Close() })
	defer stop()
	touch := func() { conn.SetDeadline(time.Now().Add(time.Duration(c.IdleSeconds) * time.Second)) }
	touch()
	results := make(chan error, 2)
	go func() {
		for {
			select {
			case <-f.ctx.Done():
				results <- f.ctx.Err()
				return
			case packet := <-f.queue:
				f.queued.Add(-int64(len(packet)))
				if err := writeDatagram(conn, packet); err != nil {
					s.dropped.Add(1)
					results <- err
					return
				}
				s.forwarded.Add(int64(len(packet)))
				s.datagramsForwarded.Add(1)
				touch()
			}
		}
	}()
	go func() {
		buffer := make([]byte, maxDatagram)
		for {
			p, err := readDatagram(conn, buffer)
			if err != nil {
				results <- err
				return
			}
			n, err := udp.WriteToUDP(p, source)
			if err != nil {
				results <- err
				return
			}
			s.returned.Add(int64(n))
			s.datagramsReturned.Add(1)
			touch()
		}
	}()
	first := <-results
	f.cancel()
	conn.Close()
	<-results
	return first
}

func serveUDPRelay(ctx context.Context, ln net.Listener, c Config, tc *tls.Config, s *Stats) error {
	return acceptBounded(ctx, ln, c.MaxConnections, func() { s.rejected.Add(1) }, func(ctx context.Context, raw net.Conn) {
		defer raw.Close()
		s.accepted.Add(1)
		s.active.Add(1)
		defer s.active.Add(-1)
		stop := context.AfterFunc(ctx, func() { raw.Close() })
		defer stop()
		conn := tls.Server(raw, tc)
		conn.SetDeadline(time.Now().Add(setupTimeout))
		if err := conn.HandshakeContext(ctx); err != nil {
			if ctx.Err() == nil {
				s.errors.Add(1)
			}
			return
		}
		if conn.ConnectionState().NegotiatedProtocol == probeALPN {
			s.probes.Add(1)
			if err := handleProbe(ctx, conn); err != nil && ctx.Err() == nil {
				s.errors.Add(1)
			}
			return
		}
		if conn.ConnectionState().NegotiatedProtocol != udpALPN {
			s.errors.Add(1)
			return
		}
		if err := relayDatagrams(ctx, conn, c, s); !normalSessionEnd(err) && ctx.Err() == nil {
			s.errors.Add(1)
		} else {
			s.completed.Add(1)
		}
	})
}

func relayDatagrams(ctx context.Context, stream net.Conn, c Config, s *Stats) error {
	d := net.Dialer{Timeout: 5 * time.Second}
	target, err := d.DialContext(ctx, "udp", c.Target)
	if err != nil {
		return err
	}
	defer target.Close()
	closeBoth := func() { stream.Close(); target.Close() }
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	touch := func() {
		deadline := time.Now().Add(time.Duration(c.IdleSeconds) * time.Second)
		stream.SetDeadline(deadline)
		target.SetDeadline(deadline)
	}
	touch()
	results := make(chan error, 2)
	go func() {
		buffer := make([]byte, maxDatagram)
		for {
			p, err := readDatagram(stream, buffer)
			if err != nil {
				results <- err
				return
			}
			n, err := target.Write(p)
			if err != nil {
				results <- err
				return
			}
			s.forwarded.Add(int64(n))
			s.datagramsForwarded.Add(1)
			touch()
		}
	}()
	go func() {
		buffer := make([]byte, 65536)
		for {
			n, err := target.Read(buffer)
			if err != nil {
				results <- err
				return
			}
			if n > maxDatagram {
				s.dropped.Add(1)
				continue
			}
			if err = writeDatagram(stream, buffer[:n]); err != nil {
				results <- err
				return
			}
			s.returned.Add(int64(n))
			s.datagramsReturned.Add(1)
			touch()
		}
	}()
	first := <-results
	closeBoth()
	<-results
	return first
}

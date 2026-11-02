package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const reverseALPN = "tunnellab-reverse/0.2"
const setupTimeout = 10 * time.Second

// Only control messages use these bounded, length-prefixed JSON frames.
// Data sockets switch to an unframed byte stream after a ready response.
type controlFrame struct {
	Type   string `json:"type"`
	Ticket string `json:"ticket,omitempty"`
}

func readFrame(r io.Reader) (controlFrame, error) {
	var f controlFrame
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return f, err
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n < 2 || n > 512 {
		return f, errors.New("invalid control frame length")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, err
	}
	return f, nil
}
func writeFrame(w io.Writer, f controlFrame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(b) > 512 {
		return errors.New("control frame too long")
	}
	p := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(p[:2], uint16(len(b)))
	copy(p[2:], b)
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

type controlSession struct {
	conn     *tls.Conn
	identity [32]byte
	done     chan struct{}
	once     sync.Once
	writeMu  sync.Mutex
}

func (s *controlSession) close() { s.once.Do(func() { close(s.done); s.conn.Close() }) }
func (s *controlSession) send(f controlFrame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	s.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if err := writeFrame(s.conn, f); err != nil {
		s.close()
		return err
	}
	return nil
}

type pendingData struct {
	session *controlSession
	conn    chan net.Conn
	done    <-chan struct{}
}
type reverseHub struct {
	mu      sync.Mutex
	control *controlSession
	pending map[string]*pendingData
	stats   *Stats
}

func newHub(s *Stats) *reverseHub {
	return &reverseHub{pending: make(map[string]*pendingData), stats: s}
}

// acceptBounded bounds handlers before TLS handshakes or request processing.
// A handler owns its connection until return, except when it explicitly hands
// the socket to another bounded handler (a reverse data socket).
func acceptBounded(ctx context.Context, ln net.Listener, limit int, reject func(), handle func(context.Context, net.Conn)) error {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	sem := make(chan struct{}, limit)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			conn.Close()
			reject()
			continue
		}
		wg.Add(1)
		go func() { defer wg.Done(); defer func() { <-sem }(); handle(ctx, conn) }()
	}
}

func serveReverseEdge(ctx context.Context, userLn, tunnelLn net.Listener, c Config, tc *tls.Config, s *Stats) error {
	return newHub(s).serve(ctx, userLn, tunnelLn, c, tc)
}
func (hub *reverseHub) serve(ctx context.Context, userLn, tunnelLn net.Listener, c Config, tc *tls.Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s := hub.stats
	results := make(chan error, 2)
	go func() {
		results <- acceptBounded(ctx, userLn, c.MaxConnections, func() { s.rejected.Add(1) }, func(workerCtx context.Context, conn net.Conn) { hub.user(workerCtx, conn, c) })
	}()
	go func() {
		results <- acceptBounded(ctx, tunnelLn, c.MaxConnections+8, func() { s.rejected.Add(1) }, func(workerCtx context.Context, conn net.Conn) { hub.transport(workerCtx, conn, tc) })
	}()
	err := <-results
	cancel()
	userLn.Close()
	tunnelLn.Close()
	other := <-results
	if err != nil {
		return err
	}
	return other
}

func (h *reverseHub) user(ctx context.Context, incoming net.Conn, c Config) {
	defer incoming.Close()
	h.stats.accepted.Add(1)
	h.stats.active.Add(1)
	defer h.stats.active.Add(-1)
	stop := context.AfterFunc(ctx, func() { incoming.Close() })
	defer stop()
	setupCtx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	ticket := make([]byte, 32)
	if _, err := rand.Read(ticket); err != nil {
		h.stats.errors.Add(1)
		return
	}
	key := hex.EncodeToString(ticket)
	h.mu.Lock()
	session := h.control
	if session == nil {
		h.mu.Unlock()
		h.stats.errors.Add(1)
		return
	}
	pending := &pendingData{session: session, conn: make(chan net.Conn), done: setupCtx.Done()}
	h.pending[key] = pending
	h.mu.Unlock()
	h.stats.pending.Add(1)
	defer func() { h.mu.Lock(); delete(h.pending, key); h.mu.Unlock() }()
	if err := session.send(controlFrame{Type: "open", Ticket: key}); err != nil {
		h.stats.pending.Add(-1)
		h.stats.errors.Add(1)
		return
	}
	var data net.Conn
	select {
	case data = <-pending.conn:
	case <-session.done:
	case <-setupCtx.Done():
	}
	h.stats.pending.Add(-1)
	if data == nil {
		if ctx.Err() == nil {
			h.stats.errors.Add(1)
		}
		return
	}
	defer data.Close()
	cancel()
	if bridge(ctx, incoming, data, time.Duration(c.IdleSeconds)*time.Second, h.stats) {
		h.stats.completed.Add(1)
	} else if ctx.Err() == nil {
		h.stats.errors.Add(1)
	}
}

func (h *reverseHub) transport(ctx context.Context, raw net.Conn, tc *tls.Config) {
	handedOff := false
	defer func() {
		if !handedOff {
			raw.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	conn := tls.Server(raw, tc)
	conn.SetDeadline(time.Now().Add(setupTimeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		if ctx.Err() == nil {
			h.stats.errors.Add(1)
		}
		return
	}
	state := conn.ConnectionState()
	if state.NegotiatedProtocol == probeALPN {
		h.stats.probes.Add(1)
		if err := handleProbe(ctx, conn); err != nil && ctx.Err() == nil {
			h.stats.errors.Add(1)
		}
		return
	}
	if state.NegotiatedProtocol != reverseALPN || len(state.PeerCertificates) == 0 {
		h.stats.errors.Add(1)
		return
	}
	f, err := readFrame(conn)
	if err != nil {
		h.stats.errors.Add(1)
		return
	}
	identity := sha256.Sum256(state.PeerCertificates[0].Raw)
	switch f.Type {
	case "control":
		session := &controlSession{conn: conn, identity: identity, done: make(chan struct{})}
		conn.SetDeadline(time.Time{})
		h.mu.Lock()
		if h.control != nil {
			h.mu.Unlock()
			writeFrame(conn, controlFrame{Type: "busy"})
			return
		}
		// A request must never reach the relay before its initial ready frame.
		if session.send(controlFrame{Type: "ready"}) != nil {
			h.mu.Unlock()
			return
		}
		h.control = session
		h.stats.controlConnected.Store(true)
		h.mu.Unlock()
		defer func() {
			session.close()
			h.mu.Lock()
			if h.control == session {
				h.control = nil
				h.stats.controlConnected.Store(false)
			}
			h.mu.Unlock()
		}()
		for {
			conn.SetReadDeadline(time.Now().Add(15 * time.Second))
			f, err := readFrame(conn)
			if err != nil {
				return
			}
			if f.Type != "ping" {
				return
			}
			if session.send(controlFrame{Type: "pong"}) != nil {
				return
			}
		}
	case "data":
		if len(f.Ticket) != 64 {
			return
		}
		h.mu.Lock()
		p := h.pending[f.Ticket]
		if p == nil || p.session.identity != identity {
			h.mu.Unlock()
			return
		}
		select {
		case <-p.session.done:
			h.mu.Unlock()
			return
		default:
		}
		delete(h.pending, f.Ticket)
		h.mu.Unlock() // Consume the ticket exactly once.
		if err := writeFrame(conn, controlFrame{Type: "ready"}); err != nil {
			return
		}
		conn.SetDeadline(time.Time{})
		select {
		case p.conn <- conn:
			handedOff = true
		case <-p.done:
		case <-ctx.Done():
		}
	default:
		return
	}
}

func dialReverse(ctx context.Context, c Config, tc *tls.Config) (*tls.Conn, error) {
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}, Config: tc}
	conn, err := d.DialContext(ctx, "tcp", c.Peer)
	if err != nil {
		return nil, err
	}
	t := conn.(*tls.Conn)
	if t.ConnectionState().NegotiatedProtocol != reverseALPN {
		t.Close()
		return nil, errors.New("reverse ALPN mismatch")
	}
	return t, nil
}

// Reconnect applies only to the control channel. Active data connections have
// the parent process context and survive control-channel replacement.
func serveReverseRelay(ctx context.Context, c Config, tc *tls.Config, s *Stats) error {
	var workers sync.WaitGroup
	defer workers.Wait()
	sem := make(chan struct{}, c.MaxConnections)
	backoff := 250 * time.Millisecond
	for ctx.Err() == nil {
		start := time.Now()
		err := relaySession(ctx, c, tc, s, sem, &workers)
		s.controlConnected.Store(false)
		if ctx.Err() != nil {
			break
		}
		if err != nil {
			s.errors.Add(1)
		}
		s.controlReconnects.Add(1)
		if time.Since(start) > 10*time.Second {
			backoff = 250 * time.Millisecond
		}
		// Jitter prevents multiple agents from retrying in lockstep.
		var jitter [1]byte
		rand.Read(jitter[:])
		delay := backoff + time.Duration(jitter[0])*time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
		if backoff < 4*time.Second {
			backoff *= 2
		}
	}
	return nil
}

func relaySession(ctx context.Context, c Config, tc *tls.Config, s *Stats, sem chan struct{}, workers *sync.WaitGroup) error {
	setupCtx, cancel := context.WithTimeout(ctx, setupTimeout)
	conn, err := dialReverse(setupCtx, c, tc)
	cancel()
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(setupTimeout))
	if err = writeFrame(conn, controlFrame{Type: "control"}); err != nil {
		return err
	}
	f, err := readFrame(conn)
	if err != nil {
		return err
	}
	if f.Type != "ready" {
		return errors.New("control session not accepted")
	}
	conn.SetDeadline(time.Time{})
	session := &controlSession{conn: conn, done: make(chan struct{})}
	defer session.close()
	s.controlConnected.Store(true)
	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				session.close()
				return
			case <-session.done:
				return
			case <-ticker.C:
				if session.send(controlFrame{Type: "ping"}) != nil {
					return
				}
			}
		}
	}()
	defer func() { session.close(); <-pingDone }()
	for {
		conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		f, err := readFrame(conn)
		if err != nil {
			return err
		}
		switch f.Type {
		case "pong":
			continue
		case "open":
			if len(f.Ticket) != 64 {
				return errors.New("invalid ticket")
			}
			if _, err := hex.DecodeString(f.Ticket); err != nil {
				return err
			}
			select {
			case sem <- struct{}{}:
			default:
				s.rejected.Add(1)
				continue
			}
			workers.Add(1)
			s.accepted.Add(1)
			s.active.Add(1)
			go func(ticket string) {
				defer workers.Done()
				defer func() { <-sem; s.active.Add(-1) }()
				if err := relayData(ctx, c, tc, s, ticket); err != nil && ctx.Err() == nil {
					s.errors.Add(1)
				}
			}(f.Ticket)
		default:
			return errors.New("unexpected control message")
		}
	}
}

func relayData(ctx context.Context, c Config, tc *tls.Config, s *Stats, ticket string) error {
	setupCtx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	conn, err := dialReverse(setupCtx, c, tc)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(setupTimeout))
	dialer := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	target, err := dialer.DialContext(setupCtx, "tcp", c.Target)
	if err != nil {
		return err
	}
	defer target.Close()
	if err = writeFrame(conn, controlFrame{Type: "data", Ticket: ticket}); err != nil {
		return err
	}
	f, err := readFrame(conn)
	if err != nil {
		return err
	}
	if f.Type != "ready" {
		return errors.New("data session not accepted")
	}
	cancel()
	conn.SetDeadline(time.Time{})
	if bridge(ctx, conn, target, time.Duration(c.IdleSeconds)*time.Second, s) {
		s.completed.Add(1)
		return nil
	}
	return errors.New("data transfer failed")
}

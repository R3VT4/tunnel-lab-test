package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

const quicALPN = "tunnellab-quic/0.1"
const quicAbort = quic.StreamErrorCode(0x100)

func quicConfig(c Config) *quic.Config {
	config := &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 60 * time.Second,
		KeepAlivePeriod: 15 * time.Second, MaxIncomingStreams: int64(c.MaxConnections),
		MaxIncomingUniStreams: -1, Allow0RTT: false, EnableDatagrams: false,
		InitialStreamReceiveWindow: 256 * 1024, MaxStreamReceiveWindow: 2 * 1024 * 1024,
		InitialConnectionReceiveWindow: 512 * 1024, MaxConnectionReceiveWindow: 8 * 1024 * 1024,
	}
	if c.Mode == "edge" {
		config.MaxIncomingStreams = -1
	}
	return config
}

// Stream close must not reset data already queued before a successful FIN.
// The shared QUIC session outlives each stream so it can deliver those bytes.
type quicStreamConn struct {
	stream   *quic.Stream
	conn     *quic.Conn
	mu       sync.Mutex
	writeFIN bool
}

func (q *quicStreamConn) Read(p []byte) (int, error)  { return q.stream.Read(p) }
func (q *quicStreamConn) Write(p []byte) (int, error) { return q.stream.Write(p) }
func (q *quicStreamConn) CloseWrite() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	err := q.stream.Close()
	if err == nil {
		q.writeFIN = true
	}
	return err
}
func (q *quicStreamConn) Close() error {
	q.stream.CancelRead(quicAbort)
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.writeFIN {
		q.stream.CancelWrite(quicAbort)
	}
	return nil
}
func (q *quicStreamConn) LocalAddr() net.Addr                { return q.conn.LocalAddr() }
func (q *quicStreamConn) RemoteAddr() net.Addr               { return q.conn.RemoteAddr() }
func (q *quicStreamConn) SetDeadline(t time.Time) error      { return q.stream.SetDeadline(t) }
func (q *quicStreamConn) SetReadDeadline(t time.Time) error  { return q.stream.SetReadDeadline(t) }
func (q *quicStreamConn) SetWriteDeadline(t time.Time) error { return q.stream.SetWriteDeadline(t) }

// One authenticated session is reused by independent streams. A dead session is
// replaced only for a new flow; failed active streams are never replayed.
type quicPool struct {
	mu     sync.Mutex
	conn   *quic.Conn
	config Config
	tls    *tls.Config
	closed bool
}

func (p *quicPool) session(ctx context.Context) (*quic.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, atStage("quic_handshake", net.ErrClosed)
	}
	if err := ctx.Err(); err != nil {
		return nil, atStage("quic_handshake", err)
	}
	if p.conn != nil && p.conn.Context().Err() == nil {
		return p.conn, nil
	}
	conn, err := quic.DialAddr(ctx, p.config.Peer, p.tls.Clone(), quicConfig(p.config))
	if err != nil {
		return nil, atStage("quic_handshake", fmt.Errorf("QUIC handshake: %w", err))
	}
	p.conn = conn
	return conn, nil
}
func (p *quicPool) Open(ctx context.Context, protocol string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	conn, err := p.session(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, atStage("quic_stream", err)
	}
	q := &quicStreamConn{stream: stream, conn: conn}
	ok := false
	defer func() {
		if !ok {
			q.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { q.Close() })
	defer stop()
	if deadline, has := ctx.Deadline(); has {
		q.SetDeadline(deadline)
	}
	header, err := protocolHeader(protocol)
	if err != nil {
		return nil, err
	}
	if protocol != "tunnellab/0.1" && protocol != probeALPN {
		return nil, errors.New("unsupported QUIC stream protocol")
	}
	if err = writeAll(q, header); err != nil {
		return nil, atStage("protocol_negotiation", err)
	}
	var ack [6]byte
	if _, err = io.ReadFull(q, ack[:]); err != nil {
		return nil, atStage("protocol_negotiation", err)
	}
	if !bytes.Equal(header, ack[:]) {
		return nil, atStage("protocol_negotiation", errors.New("QUIC stream acknowledgement mismatch"))
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	q.SetDeadline(time.Time{})
	ok = true
	return q, nil
}
func (p *quicPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.conn != nil {
		p.conn.CloseWithError(0, "shutdown")
	}
}

func serverQUICProtocol(conn net.Conn) (string, error) {
	var header [6]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", err
	}
	for _, protocol := range []string{"tunnellab/0.1", probeALPN} {
		want, _ := protocolHeader(protocol)
		if bytes.Equal(header[:], want) {
			return protocol, writeAll(conn, want)
		}
	}
	return "", errors.New("invalid QUIC stream preface")
}

// Adapt authenticated incoming QUIC streams to the existing Direct admission
// and bridge code. Bound sessions separately from the global stream/flow cap.
type quicNetListener struct {
	listener *quic.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	streams  chan net.Conn
	wg       sync.WaitGroup
	once     sync.Once
}

func listenQUIC(address string, c Config, tc *tls.Config) (net.Listener, error) {
	listener, err := quic.ListenAddr(address, tc.Clone(), quicConfig(c))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &quicNetListener{listener: listener, ctx: ctx, cancel: cancel, streams: make(chan net.Conn)}
	slots := make(chan struct{}, min(c.MaxConnections, 16))
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		defer cancel()
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				conn.CloseWithError(1, "session limit")
				continue
			}
			l.wg.Add(1)
			go func() {
				defer l.wg.Done()
				defer func() { <-slots }()
				stop := context.AfterFunc(ctx, func() { conn.CloseWithError(0, "shutdown") })
				defer stop()
				defer conn.CloseWithError(0, "session ended")
				for {
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					q := &quicStreamConn{stream: stream, conn: conn}
					select {
					case l.streams <- q:
					case <-ctx.Done():
						q.Close()
						return
					}
				}
			}()
		}
	}()
	return l, nil
}
func (l *quicNetListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.streams:
		if l.ctx.Err() != nil {
			conn.Close()
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}
func (l *quicNetListener) Addr() net.Addr { return l.listener.Addr() }
func (l *quicNetListener) Close() error {
	l.once.Do(func() { l.cancel(); l.listener.Close(); l.wg.Wait() })
	return nil
}

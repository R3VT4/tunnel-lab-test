package main

import (
	"context"
	"crypto/tls"
	"errors"
	quic "github.com/quic-go/quic-go"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Events deliberately contain fixed categories, not raw errors, payloads,
// addresses, certificates or reverse tickets. The history has a fixed bound.
type connectionEvent struct {
	Time      string `json:"time"`
	Stage     string `json:"stage"`
	Kind      string `json:"kind"`
	Side      string `json:"side,omitempty"`
	Operation string `json:"operation,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

type connectionDiagnostics struct {
	setupActive            atomic.Int64
	forwardingActive       atomic.Int64
	probeActive            atomic.Int64
	halfClosedActive       atomic.Int64
	halfCloseAlreadyClosed atomic.Int64
	peakActive             atomic.Int64
	setupFailures          atomic.Int64
	tcpFailures            atomic.Int64
	tlsFailures            atomic.Int64
	quicFailures           atomic.Int64
	quicStreamFailures     atomic.Int64
	protocolFailures       atomic.Int64
	targetFailures         atomic.Int64
	probeFailures          atomic.Int64
	idleTimeouts           atomic.Int64
	peerDisconnects        atomic.Int64
	transferFailures       atomic.Int64
	shutdownClosed         atomic.Int64
	mu                     sync.Mutex
	lastError              *connectionEvent
	recent                 []connectionEvent
	transferFailureCounts  map[string]int64
}

func (d *connectionDiagnostics) noteActive(n int64) {
	for old := d.peakActive.Load(); n > old; old = d.peakActive.Load() {
		if d.peakActive.CompareAndSwap(old, n) {
			return
		}
	}
}

func (d *connectionDiagnostics) event(stage, kind string, failure bool) {
	e := connectionEvent{Time: time.Now().UTC().Format(time.RFC3339Nano), Stage: stage, Kind: kind}
	d.recordEvent(e, failure, false)
}

func (d *connectionDiagnostics) recordEvent(e connectionEvent, failure, transferFailure bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if transferFailure {
		if d.transferFailureCounts == nil {
			d.transferFailureCounts = make(map[string]int64)
		}
		// Every component comes from a fixed internal vocabulary.
		d.transferFailureCounts[e.Side+"."+e.Operation+"."+e.ErrorCode]++
	}
	if failure {
		copy := e
		d.lastError = &copy
	}
	if len(d.recent) == 8 {
		copy(d.recent, d.recent[1:])
		d.recent = d.recent[:7]
	}
	d.recent = append(d.recent, e)
}

func (d *connectionDiagnostics) snapshot() map[string]any {
	d.mu.Lock()
	var last *connectionEvent
	if d.lastError != nil {
		copy := *d.lastError
		last = &copy
	}
	recent := append([]connectionEvent{}, d.recent...)
	counts := make(map[string]int64, len(d.transferFailureCounts))
	for key, count := range d.transferFailureCounts {
		counts[key] = count
	}
	d.mu.Unlock()
	return map[string]any{
		"scope": "direct_tcp", "setup_active": d.setupActive.Load(),
		"forwarding_active": d.forwardingActive.Load(), "probe_active": d.probeActive.Load(),
		"half_closed_active": d.halfClosedActive.Load(), "peak_active": d.peakActive.Load(),
		"half_close_already_closed": d.halfCloseAlreadyClosed.Load(),
		"setup_failures":            d.setupFailures.Load(), "probe_failures": d.probeFailures.Load(),
		"setup_failure_counts": map[string]int64{"tcp_connect": d.tcpFailures.Load(), "tls_handshake": d.tlsFailures.Load(), "quic_handshake": d.quicFailures.Load(), "quic_stream": d.quicStreamFailures.Load(), "protocol_negotiation": d.protocolFailures.Load(), "target_connect": d.targetFailures.Load()},
		"idle_timeouts":        d.idleTimeouts.Load(), "peer_disconnects": d.peerDisconnects.Load(),
		"transfer_failures": d.transferFailures.Load(), "shutdown_closed": d.shutdownClosed.Load(),
		"last_error": last, "recent_events": recent,
		"transfer_failure_counts": counts,
	}
}

type transportStageError struct {
	stage string
	err   error
}

func (e *transportStageError) Error() string { return e.err.Error() }
func (e *transportStageError) Unwrap() error { return e.err }
func atStage(stage string, err error) error  { return &transportStageError{stage: stage, err: err} }

func errorKind(err error) string {
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var idle *quic.IdleTimeoutError
	if errors.As(err, &idle) {
		return "quic_connection_timeout"
	}
	var stream *quic.StreamError
	if errors.As(err, &stream) {
		return "quic_stream_reset"
	}
	var application *quic.ApplicationError
	if errors.As(err, &application) {
		return "quic_connection_closed"
	}
	var transport *quic.TransportError
	if errors.As(err, &transport) {
		return "quic_transport_error"
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return "peer_disconnect"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection_refused"
	}
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) {
		return "certificate_verification"
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return "unexpected_eof"
	}
	if errors.Is(err, io.EOF) {
		return "eof"
	}
	return "io_error"
}

func (s *Stats) setupFailed(ctx context.Context, stage string, err error) {
	if ctx.Err() != nil {
		return
	}
	var typed *transportStageError
	if errors.As(err, &typed) {
		stage = typed.stage
	}
	s.errors.Add(1)
	s.diagnostics.setupFailures.Add(1)
	switch stage {
	case "tcp_connect":
		s.diagnostics.tcpFailures.Add(1)
	case "tls_handshake":
		s.diagnostics.tlsFailures.Add(1)
	case "quic_handshake":
		s.diagnostics.quicFailures.Add(1)
	case "quic_stream":
		s.diagnostics.quicStreamFailures.Add(1)
	case "protocol_negotiation":
		s.diagnostics.protocolFailures.Add(1)
	case "target_connect":
		s.diagnostics.targetFailures.Add(1)
	}
	s.diagnostics.event(stage, errorKind(err), true)
}

type bridgeResult struct {
	reason string
	err    error
}

// These wrappers retain errors.Is/As and carry no payload or endpoint address.
type bridgeIOError struct {
	side, operation string
	err             error
}

func (e *bridgeIOError) Error() string { return e.err.Error() }
func (e *bridgeIOError) Unwrap() error { return e.err }
func atBridgeIO(side, operation string, err error) error {
	return &bridgeIOError{side: side, operation: operation, err: err}
}

func bridgeErrorCode(err error) string {
	// Symbolic codes only: unknown error strings must never reach the API.
	for _, entry := range []struct {
		err  error
		code string
	}{
		{syscall.ENOTCONN, "not_connected"},
		{syscall.EBADF, "bad_file_descriptor"},
		{syscall.ESHUTDOWN, "socket_shutdown"},
		{syscall.ECONNABORTED, "connection_aborted"},
		{syscall.ECONNRESET, "connection_reset"},
		{syscall.EPIPE, "broken_pipe"},
		{net.ErrClosed, "net_closed"},
		{io.ErrClosedPipe, "closed_pipe"},
		{io.ErrShortWrite, "short_write"},
	} {
		if errors.Is(err, entry.err) {
			return entry.code
		}
	}
	return errorKind(err)
}

func (d *connectionDiagnostics) transferEvent(result bridgeResult, failure bool) {
	e := connectionEvent{Time: time.Now().UTC().Format(time.RFC3339Nano), Stage: "transfer", Kind: result.reason}
	var detail *bridgeIOError
	if errors.As(result.err, &detail) {
		switch detail.side {
		case "client", "tunnel", "target", "left", "right":
			e.Side = detail.side
		default:
			e.Side = "unknown"
		}
		switch detail.operation {
		case "read", "write", "close_write":
			e.Operation = detail.operation
		default:
			e.Operation = "unknown"
		}
	} else {
		e.Side, e.Operation = "unknown", "unknown"
	}
	e.ErrorCode = bridgeErrorCode(result.err)
	d.recordEvent(e, failure, failure)
}

func (s *Stats) transferFinished(result bridgeResult) {
	switch result.reason {
	case "eof":
		s.completed.Add(1)
	case "canceled":
		s.diagnostics.shutdownClosed.Add(1)
	case "timeout":
		s.diagnostics.idleTimeouts.Add(1)
		result.reason = "idle_timeout"
		s.diagnostics.transferEvent(result, false)
	case "peer_disconnect":
		s.errors.Add(1)
		s.diagnostics.peerDisconnects.Add(1)
		s.diagnostics.transferEvent(result, true)
	default:
		s.errors.Add(1)
		s.diagnostics.transferFailures.Add(1)
		s.diagnostics.transferEvent(result, true)
	}
}

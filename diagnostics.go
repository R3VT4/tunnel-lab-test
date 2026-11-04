package main

import (
	"context"
	"crypto/tls"
	"errors"
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
	Time  string `json:"time"`
	Stage string `json:"stage"`
	Kind  string `json:"kind"`
}

type connectionDiagnostics struct {
	setupActive      atomic.Int64
	forwardingActive atomic.Int64
	probeActive      atomic.Int64
	halfClosedActive atomic.Int64
	peakActive       atomic.Int64
	setupFailures    atomic.Int64
	tcpFailures      atomic.Int64
	tlsFailures      atomic.Int64
	protocolFailures atomic.Int64
	targetFailures   atomic.Int64
	probeFailures    atomic.Int64
	idleTimeouts     atomic.Int64
	peerDisconnects  atomic.Int64
	transferFailures atomic.Int64
	shutdownClosed   atomic.Int64
	mu               sync.Mutex
	lastError        *connectionEvent
	recent           []connectionEvent
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
	d.mu.Lock()
	defer d.mu.Unlock()
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
	d.mu.Unlock()
	return map[string]any{
		"scope": "direct_tcp", "setup_active": d.setupActive.Load(),
		"forwarding_active": d.forwardingActive.Load(), "probe_active": d.probeActive.Load(),
		"half_closed_active": d.halfClosedActive.Load(), "peak_active": d.peakActive.Load(),
		"setup_failures": d.setupFailures.Load(), "probe_failures": d.probeFailures.Load(),
		"setup_failure_counts": map[string]int64{"tcp_connect": d.tcpFailures.Load(), "tls_handshake": d.tlsFailures.Load(), "protocol_negotiation": d.protocolFailures.Load(), "target_connect": d.targetFailures.Load()},
		"idle_timeouts":        d.idleTimeouts.Load(), "peer_disconnects": d.peerDisconnects.Load(),
		"transfer_failures": d.transferFailures.Load(), "shutdown_closed": d.shutdownClosed.Load(),
		"last_error": last, "recent_events": recent,
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

func (s *Stats) transferFinished(result bridgeResult) {
	switch result.reason {
	case "eof":
		s.completed.Add(1)
	case "canceled":
		s.diagnostics.shutdownClosed.Add(1)
	case "timeout":
		s.diagnostics.idleTimeouts.Add(1)
		s.diagnostics.event("transfer", "idle_timeout", false)
	case "peer_disconnect":
		s.errors.Add(1)
		s.diagnostics.peerDisconnects.Add(1)
		s.diagnostics.event("transfer", "peer_disconnect", true)
	default:
		s.errors.Add(1)
		s.diagnostics.transferFailures.Add(1)
		s.diagnostics.event("transfer", result.reason, true)
	}
}

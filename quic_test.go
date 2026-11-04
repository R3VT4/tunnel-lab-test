package main

import (
	"bytes"
	"context"
	"encoding/json"
	quic "github.com/quic-go/quic-go"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func quicTestConfigs(t *testing.T) (Config, Config) {
	e, r := testConfigs(t)
	e.Transport = "quic"
	r.Transport = "quic"
	e.OmitSNI = true
	r.Target = echoTarget(t, true).Addr().String()
	return e, r
}
func startQUICRelay(t *testing.T, r Config) (string, *Stats, context.CancelFunc) {
	t.Helper()
	tc, err := tlsConfig(r)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := listenQUIC("127.0.0.1:0", r, tc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := newStats()
	s.quicEnabled.Store(true)
	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln, r, tc, s) }()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("QUIC shutdown hung")
		}
	})
	return ln.Addr().String(), s, cancel
}
func testQUICPool(t *testing.T, e Config) *quicPool {
	t.Helper()
	tc, err := tlsConfig(e)
	if err != nil {
		t.Fatal(err)
	}
	p := &quicPool{config: e, tls: tc}
	t.Cleanup(p.Close)
	return p
}
func TestQUICConcurrentDirectHalfCloseAndProbe(t *testing.T) {
	e, r := quicTestConfigs(t)
	peer, rs, _ := startQUICRelay(t, r)
	e.Peer = peer
	addr, es, _ := startEngine(t, e)
	want := bytes.Repeat([]byte("QUIC binary\x00\xff"), 32768)
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(8 * time.Second))
			if err = writeAll(c, want); err != nil {
				t.Error(err)
				return
			}
			c.(*net.TCPConn).CloseWrite()
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, want) {
				t.Errorf("QUIC payload mismatch len=%d: %v", len(got), err)
			}
		}()
	}
	wg.Wait()
	waitFor(t, func() bool { return es.completed.Load() == 6 && rs.completed.Load() == 6 })
	if es.returned.Load() != int64(6*len(want)) || rs.forwarded.Load() != int64(6*len(want)) {
		t.Fatal("incorrect QUIC byte counts")
	}
	tc, _ := tlsConfig(e)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	report, err := runProbe(ctx, e, tc, 262144, 3)
	if err != nil {
		t.Fatal(err)
	}
	if report.Transport != "quic/udp/tls1.3" || report.QUICSetupMS == nil || report.SetupMS != 0 || report.PacketLossMeasured {
		t.Fatalf("mislabelled QUIC probe: %+v", report)
	}
	if es.snapshot("edge")["connection_diagnostics"].(map[string]any)["scope"] != "direct_quic_streams" {
		t.Fatal("wrong diagnostic scope")
	}
}
func TestQUICStreamResetDoesNotAbortSibling(t *testing.T) {
	e, r := quicTestConfigs(t)
	e.Peer, _, _ = startQUICRelay(t, r)
	p := testQUICPool(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := p.Open(ctx, "tunnellab/0.1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.Open(ctx, "tunnellab/0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first.(*quicStreamConn).conn != second.(*quicStreamConn).conn {
		t.Fatal("streams did not share session")
	}
	first.Close()
	want := bytes.Repeat([]byte("sibling survives"), 10000)
	if err := writeAll(second, want); err != nil {
		t.Fatal(err)
	}
	second.(*quicStreamConn).CloseWrite()
	got, err := io.ReadAll(second)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("sibling stream failed: %v", err)
	}
}
func TestQUICReconnectsOnlyNewFlows(t *testing.T) {
	e, r := quicTestConfigs(t)
	e.Peer, _, _ = startQUICRelay(t, r)
	p := testQUICPool(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := p.Open(ctx, "tunnellab/0.1")
	if err != nil {
		t.Fatal(err)
	}
	old := first.(*quicStreamConn).conn
	old.CloseWithError(3, "test disconnect")
	if _, err := first.Read(make([]byte, 1)); err == nil {
		t.Fatal("old stream survived closed connection")
	}
	first.Close()
	next, err := p.Open(ctx, "tunnellab/0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if next.(*quicStreamConn).conn == old {
		t.Fatal("dead session reused")
	}
	if err := writeAll(next, []byte("new flow")); err != nil {
		t.Fatal(err)
	}
	next.(*quicStreamConn).CloseWrite()
	got, err := io.ReadAll(next)
	if err != nil || string(got) != "new flow" {
		t.Fatalf("new flow failed: %v", err)
	}
}
func TestQUICRejectsUntrustedIdentities(t *testing.T) {
	e, r := quicTestConfigs(t)
	e.Peer, _, _ = startQUICRelay(t, r)
	other, _ := testConfigs(t)
	for _, kind := range []string{"wrong_ca", "wrong_name", "missing_client_certificate", "wrong_alpn"} {
		t.Run(kind, func(t *testing.T) {
			c := e
			if kind == "wrong_ca" {
				c.CA = other.CA
			}
			if kind == "wrong_name" {
				c.ServerName = "wrong.invalid"
			}
			tc, err := tlsConfig(c)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "missing_client_certificate" {
				tc.Certificates = nil
			}
			if kind == "wrong_alpn" {
				tc.NextProtos = []string{"wrong"}
			}
			p := &quicPool{config: c, tls: tc}
			defer p.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			defer cancel()
			conn, err := p.Open(ctx, "tunnellab/0.1")
			if err == nil {
				conn.Close()
				t.Fatal("unauthorized QUIC stream accepted")
			}
		})
	}
}
func TestQUICMalformedStreamKeepsSessionUsable(t *testing.T) {
	e, r := quicTestConfigs(t)
	peer, s, _ := startQUICRelay(t, r)
	e.Peer = peer
	p := testQUICPool(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := p.session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(time.Now().Add(time.Second))
	stream.Write([]byte("BADBAD"))
	if _, err = stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("bad preface accepted")
	}
	waitFor(t, func() bool { return s.diagnostics.protocolFailures.Load() == 1 && s.active.Load() == 0 })
	valid, err := p.Open(ctx, "tunnellab/0.1")
	if err != nil {
		t.Fatal(err)
	}
	valid.Close()
	if conn.ConnectionState().Used0RTT {
		t.Fatal("unexpected 0-RTT")
	}
}
func TestQUICStreamCapacityAndRelease(t *testing.T) {
	e, r := quicTestConfigs(t)
	r.MaxConnections = 1
	peer, s, _ := startQUICRelay(t, r)
	e.Peer = peer
	p := testQUICPool(t, e)
	first, err := p.Open(context.Background(), "tunnellab/0.1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if second, err := p.Open(ctx, "tunnellab/0.1"); err == nil {
		second.Close()
		t.Fatal("stream credit limit bypassed")
	}
	first.Close()
	waitFor(t, func() bool { return s.active.Load() == 0 })
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	next, err := p.Open(ctx2, "tunnellab/0.1")
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}
func TestQUICIdleAndShutdownReleaseFlows(t *testing.T) {
	e, r := quicTestConfigs(t)
	r.IdleSeconds = 1
	peer, s, stop := startQUICRelay(t, r)
	e.Peer = peer
	p := testQUICPool(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := p.Open(ctx, "tunnellab/0.1")
	if err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle stream remained open")
	}
	conn.Close()
	waitFor(t, func() bool { return s.active.Load() == 0 && s.diagnostics.idleTimeouts.Load() == 1 })
	conn, err = p.Open(ctx, "tunnellab/0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	stop()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("stream not closed on shutdown")
	}
}
func TestQUICConfigurationAndBindings(t *testing.T) {
	e, r := quicTestConfigs(t)
	for _, mode := range []string{"reverse-edge", "reverse-relay", "udp-edge", "udp-relay"} {
		c := e
		c.Mode = mode
		path := filepath.Join(t.TempDir(), "config.json")
		b, _ := json.Marshal(c)
		os.WriteFile(path, b, 0600)
		if _, err := loadConfig(path); err == nil {
			t.Fatal("unsupported QUIC mode accepted")
		}
	}
	e.ProtocolNegotiation = "encrypted-preface"
	path := filepath.Join(t.TempDir(), "config.json")
	b, _ := json.Marshal(e)
	os.WriteFile(path, b, 0600)
	if _, err := loadConfig(path); err == nil {
		t.Fatal("QUIC allowed missing ALPN profile")
	}
	if configBindings(r)[1].network != "udp" {
		t.Fatal("QUIC relay listener not UDP")
	}
	r.Transport = "tcp"
	if configBindings(r)[1].network != "tcp" {
		t.Fatal("TCP default binding changed")
	}
	if quicConfig(r).Allow0RTT || quicConfig(r).EnableDatagrams {
		t.Fatal("unsupported early data/datagrams enabled")
	}
}

func TestQUICConnectionTimeoutIsNotApplicationIdle(t *testing.T) {
	s := newStats()
	err := &quic.IdleTimeoutError{}
	s.transferFinished(bridgeResult{reason: errorKind(err), err: atBridgeIO("tunnel", "read", err)})
	if s.diagnostics.idleTimeouts.Load() != 0 || s.diagnostics.transferFailures.Load() != 1 || s.errors.Load() != 1 {
		t.Fatal("QUIC path timeout hidden as application idle")
	}
}

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testConfigs(t *testing.T) (Config, Config) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "credentials")
	if err := initDemo(dir); err != nil {
		t.Fatal(err)
	}
	e, err := loadConfig(filepath.Join(dir, "edge.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := loadConfig(filepath.Join(dir, "relay.json"))
	if err != nil {
		t.Fatal(err)
	}
	return e, r
}
func startEngine(t *testing.T, c Config) (string, *Stats, context.CancelFunc) {
	t.Helper()
	tc, err := tlsConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := newStats()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln, c, tc, s) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("engine shutdown hung")
		}
	})
	return ln.Addr().String(), s, cancel
}
func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition timed out")
}

func TestEndToEndMutualTLSHalfCloseAndConcurrentTransfers(t *testing.T) {
	e, r := testConfigs(t)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				b, err := io.ReadAll(c)
				if err == nil {
					c.Write(b)
				}
			}()
		}
	}()
	r.Target = target.Addr().String()
	relay, rs, _ := startEngine(t, r)
	e.Peer = relay
	edge, es, _ := startEngine(t, e)
	const clients = 6
	payload := bytes.Repeat([]byte("\x00tunnel-lab\xff\n"), 40000)
	var wg sync.WaitGroup
	for range clients {
		wg.Go(func() {
			c, err := net.DialTimeout("tcp", edge, time.Second)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(8 * time.Second))
			if _, err = c.Write(payload); err != nil {
				t.Error(err)
				return
			}
			if err = c.(*net.TCPConn).CloseWrite(); err != nil {
				t.Error(err)
				return
			}
			got, err := io.ReadAll(c)
			if err != nil {
				t.Error(err)
				return
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("payload mismatch: got %d want %d", len(got), len(payload))
			}
		})
	}
	wg.Wait()
	waitFor(t, func() bool { return es.active.Load() == 0 && rs.active.Load() == 0 })
	for _, s := range []*Stats{es, rs} {
		if s.errors.Load() != 0 {
			t.Errorf("unexpected errors: %d", s.errors.Load())
		}
		if s.forwarded.Load() != int64(clients*len(payload)) || s.returned.Load() != int64(clients*len(payload)) {
			t.Errorf("bad byte counts: %+v", s.snapshot("test"))
		}
	}
}

func TestRejectClientWithoutCertificate(t *testing.T) {
	e, r := testConfigs(t)
	addr, s, _ := startEngine(t, r)
	tc, err := tlsConfig(e)
	if err != nil {
		t.Fatal(err)
	}
	tc.Certificates = nil
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, tc)
	if err == nil {
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		c.Write([]byte("unauthorized"))
		_, err = c.Read(make([]byte, 1))
	}
	if err == nil {
		t.Fatal("client without certificate accepted")
	}
	waitFor(t, func() bool { return s.errors.Load() == 1 })
}

func TestRejectUntrustedCAAndWrongServerIdentity(t *testing.T) {
	e, r := testConfigs(t)
	other, _ := testConfigs(t)
	addr, _, _ := startEngine(t, r)
	for _, c := range []Config{other, e} {
		if c.CA == e.CA {
			c.ServerName = "wrong.example"
		}
		tc, err := tlsConfig(c)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, tc)
		if err == nil {
			conn.Close()
			t.Fatal("untrusted peer accepted")
		}
	}
}

func TestConnectionLimitAndShutdownDuringHandshake(t *testing.T) {
	_, r := testConfigs(t)
	r.MaxConnections = 1
	addr, s, cancel := startEngine(t, r)
	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	waitFor(t, func() bool { return s.active.Load() == 1 })
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	waitFor(t, func() bool { return s.rejected.Load() == 1 })
	cancel()
	waitFor(t, func() bool { return s.active.Load() == 0 })
}

func TestBridgeIdleTimeout(t *testing.T) {
	l1, l2 := net.Pipe()
	r1, r2 := net.Pipe()
	defer l1.Close()
	defer l2.Close()
	defer r1.Close()
	defer r2.Close()
	done := make(chan bool, 1)
	go func() { done <- bridge(context.Background(), l1, r1, 30*time.Millisecond, newStats()) }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("idle timeout reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("idle connections leaked")
	}
}

func TestAdminReadOnlyAndRebindingProtection(t *testing.T) {
	h := adminHandler(Config{Mode: "edge"}, newStats())
	for _, tt := range []struct {
		method, path, host string
		status             int
	}{{"GET", "/api/status", "127.0.0.1:9081", 200}, {"GET", "/", "127.0.0.1:9081", 200}, {"POST", "/api/status", "127.0.0.1:9081", 405}, {"GET", "/api/status", "attacker.example", 403}, {"GET", "/missing", "127.0.0.1:9081", 404}} {
		r := httptest.NewRequest(tt.method, "http://"+tt.host+tt.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tt.status {
			t.Errorf("%+v got %d", tt, w.Code)
		}
		if tt.path == "/api/status" && w.Code == 200 {
			var got map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got["mode"] != "edge" {
				t.Fatal(got)
			}
		}
	}
}

func TestConfigRejectsPublicAdminAndUnknownFields(t *testing.T) {
	e, _ := testConfigs(t)
	for _, mutate := range []func(map[string]any){func(m map[string]any) { m["admin"] = "0.0.0.0:9081" }, func(m map[string]any) { m["max_connections"] = 0 }, func(m map[string]any) { m["unknown"] = true }} {
		b, _ := json.Marshal(e)
		var m map[string]any
		json.Unmarshal(b, &m)
		mutate(m)
		b, _ = json.Marshal(m)
		p := filepath.Join(t.TempDir(), "bad.json")
		os.WriteFile(p, b, 0600)
		if _, err := loadConfig(p); err == nil {
			t.Fatal("bad config accepted")
		}
	}
}

func TestInitDoesNotOverwriteExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "keep")
	os.WriteFile(marker, []byte("unchanged"), 0600)
	if err := initDemo(dir); err == nil {
		t.Fatal("expected error")
	}
	b, err := os.ReadFile(marker)
	if err != nil || string(b) != "unchanged" {
		t.Fatal("existing content changed")
	}
}

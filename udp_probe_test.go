package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func udpEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	c := listenUDP(t)
	t.Cleanup(func() { c.Close() })
	go func() {
		b := make([]byte, 65536)
		for {
			n, addr, err := c.ReadFromUDP(b)
			if err != nil {
				return
			}
			c.WriteToUDP(b[:n], addr)
		}
	}()
	return c
}
func startUDPRelay(t *testing.T, r Config, target string) (string, *Stats) {
	t.Helper()
	r.Mode = "udp-relay"
	r.Target = target
	tc, err := tlsConfig(r)
	if err != nil {
		t.Fatal(err)
	}
	ln := listenLocal(t)
	ctx, cancel := context.WithCancel(context.Background())
	s := newStats()
	done := make(chan error, 1)
	go func() { done <- serveUDPRelay(ctx, ln, r, tc, s) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("UDP relay shutdown hung")
		}
	})
	return ln.Addr().String(), s
}
func startUDPEdge(t *testing.T, e Config, peer string) (string, *Stats) {
	t.Helper()
	e.Mode = "udp-edge"
	e.Peer = peer
	tc, err := tlsConfig(e)
	if err != nil {
		t.Fatal(err)
	}
	udp := listenUDP(t)
	ctx, cancel := context.WithCancel(context.Background())
	s := newStats()
	done := make(chan error, 1)
	go func() { done <- serveUDPEdge(ctx, udp, e, tc, s) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("UDP edge shutdown hung")
		}
	})
	return udp.LocalAddr().String(), s
}

func TestUDPDatagramBoundariesZeroAndMaximumPayload(t *testing.T) {
	e, r := testConfigs(t)
	target := udpEcho(t)
	relay, rs := startUDPRelay(t, r, target.LocalAddr().String())
	edge, es := startUDPEdge(t, e, relay)
	conn, err := net.Dial("udp", edge)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	payloads := [][]byte{{}, []byte("one"), bytes.Repeat([]byte{0, 255, 128, 1}, 4096), bytes.Repeat([]byte("M"), maxDatagram)}
	buffer := make([]byte, 65536)
	for _, p := range payloads {
		if _, err = conn.Write(p); err != nil {
			t.Fatal(err)
		}
		n, err := conn.Read(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buffer[:n], p) {
			t.Fatalf("datagram changed: got %d want %d", n, len(p))
		}
	}
	waitFor(t, func() bool { return es.datagramsReturned.Load() == 4 && rs.datagramsReturned.Load() == 4 })
	if es.accepted.Load() != 1 || rs.accepted.Load() != 1 {
		t.Fatal("one source should have one association")
	}
}

func TestUDPClientIsolation(t *testing.T) {
	e, r := testConfigs(t)
	target := udpEcho(t)
	relay, _ := startUDPRelay(t, r, target.LocalAddr().String())
	edge, es := startUDPEdge(t, e, relay)
	var wg sync.WaitGroup
	for id := range 6 {
		wg.Go(func() {
			conn, err := net.Dial("udp", edge)
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			buffer := make([]byte, 1024)
			for seq := range 12 {
				p := bytes.Repeat([]byte{byte(id), byte(seq)}, 200)
				if _, err := conn.Write(p); err != nil {
					t.Error(err)
					return
				}
				n, err := conn.Read(buffer)
				if err != nil {
					t.Error(err)
					return
				}
				if !bytes.Equal(p, buffer[:n]) {
					t.Error("cross-client payload mixup")
					return
				}
			}
		})
	}
	wg.Wait()
	if es.accepted.Load() != 6 {
		t.Fatal("sources not isolated")
	}
}

func TestUDPCapAndIdleExpiry(t *testing.T) {
	e, r := testConfigs(t)
	e.MaxConnections = 1
	e.IdleSeconds = 1
	r.IdleSeconds = 1
	target := udpEcho(t)
	relay, _ := startUDPRelay(t, r, target.LocalAddr().String())
	edge, s := startUDPEdge(t, e, relay)
	first, err := net.Dial("udp", edge)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	first.SetDeadline(time.Now().Add(2 * time.Second))
	first.Write([]byte("first"))
	if _, err = first.Read(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	second, err := net.Dial("udp", edge)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.Write([]byte("over cap"))
	waitFor(t, func() bool { return s.rejected.Load() > 0 })
	waitFor(t, func() bool { return s.active.Load() == 0 })
	second.SetDeadline(time.Now().Add(2 * time.Second))
	second.Write([]byte("after expiry"))
	b := make([]byte, 32)
	n, err := second.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(b[:n]) != "after expiry" {
		t.Fatal("new session failed")
	}
}

func TestUDPQueueBoundsAndFrameValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &udpFlow{ctx: ctx, cancel: cancel, queue: make(chan []byte, 8)}
	p := make([]byte, maxDatagram)
	for range 4 {
		if !f.enqueue(p) {
			t.Fatal("packet should fit")
		}
	}
	if f.enqueue(p) {
		t.Fatal("byte budget exceeded")
	}
	if f.queued.Load() > maxQueuedBytes {
		t.Fatal("queue memory exceeded")
	}
	s := newStats()
	f.discard(s)
	if s.dropped.Load() != 4 || f.queued.Load() != 0 || f.enqueue([]byte("closed")) {
		t.Fatal("queue cleanup failed")
	}
	var b bytes.Buffer
	writeDatagram(&b, []byte{})
	writeDatagram(&b, []byte("next"))
	buf := make([]byte, maxDatagram)
	if p, err := readDatagram(&b, buf); err != nil || len(p) != 0 {
		t.Fatal("empty datagram lost")
	}
	if p, err := readDatagram(&b, buf); err != nil || string(p) != "next" {
		t.Fatal("datagram boundaries lost")
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], 65535)
	if _, err := readDatagram(bytes.NewReader(header[:]), buf); err == nil {
		t.Fatal("oversize frame accepted")
	}
	if err := writeDatagram(io.Discard, make([]byte, maxDatagram+1)); err == nil {
		t.Fatal("oversize datagram accepted")
	}
	if _, err := readDatagram(bytes.NewReader([]byte{0, 2, 1}), buf); err == nil {
		t.Fatal("truncated frame accepted")
	}
}

func TestProbeOnDirectUDPAndReverseListeners(t *testing.T) {
	e, r := testConfigs(t)
	direct, _, _ := startEngine(t, r)
	udp, _ := startUDPRelay(t, r, "127.0.0.1:9")
	reverse := listenLocal(t)
	_, _ = startReverseEdge(t, e, reverse)
	for _, kind := range []string{"direct", "udp", "reverse"} {
		t.Run(kind, func(t *testing.T) {
			c := e
			switch kind {
			case "direct":
				c.Peer = direct
			case "udp":
				c.Mode = "udp-edge"
				c.Peer = udp
			case "reverse":
				c = r
				c.Mode = "reverse-relay"
				c.Peer = reverse.Addr().String()
				c.ServerName = "edge.tunnellab.local"
			}
			tc, err := tlsConfig(c)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			report, err := runProbe(ctx, c, tc, 256*1024, 4)
			if err != nil {
				t.Fatal(err)
			}
			if report.DownloadMbps <= 0 || report.UploadMbps <= 0 || report.RTTMeanMS <= 0 || report.BytesEachWay != 256*1024 || report.PacketLossMeasured {
				t.Fatalf("incorrect report %+v", report)
			}
		})
	}
}

func TestProbeBoundsAndUntrustedPeer(t *testing.T) {
	e, r := testConfigs(t)
	addr, _, _ := startEngine(t, r)
	e.Peer = addr
	tc, err := tlsConfig(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, maxProbeBytes + 1} {
		if _, err := runProbe(context.Background(), e, tc, size, 8); err == nil {
			t.Fatal("invalid size accepted")
		}
	}
	other, _ := testConfigs(t)
	other.Peer = addr
	wrongTC, err := tlsConfig(other)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := runProbe(ctx, other, wrongTC, 1024, 1); err == nil {
		t.Fatal("untrusted probe peer accepted")
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	done := make(chan error, 1)
	go func() { done <- handleProbe(context.Background(), left) }()
	header := make([]byte, 9)
	copy(header, "TLP1")
	header[4] = 1
	binary.BigEndian.PutUint32(header[5:], uint32(maxProbeBytes+1))
	right.Write(header)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("server accepted oversized probe")
		}
	case <-time.After(time.Second):
		t.Fatal("invalid probe not rejected")
	}
}

func TestProbeRejectsCorruptDownloadAndUploadReceipt(t *testing.T) {
	for _, corrupt := range []string{"download", "upload"} {
		t.Run(corrupt, func(t *testing.T) {
			e, r := testConfigs(t)
			serverTC, err := tlsConfig(r)
			if err != nil {
				t.Fatal(err)
			}
			ln := listenLocal(t)
			defer ln.Close()
			e.Peer = ln.Addr().String()
			clientTC, err := tlsConfig(e)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				raw, err := ln.Accept()
				if err != nil {
					return
				}
				defer raw.Close()
				c := tls.Server(raw, serverTC)
				c.SetDeadline(time.Now().Add(2 * time.Second))
				if c.Handshake() != nil {
					return
				}
				var header [9]byte
				if _, err := io.ReadFull(c, header[:]); err != nil {
					return
				}
				var ping [16]byte
				for range int(header[4]) {
					if _, err := io.ReadFull(c, ping[:]); err != nil {
						return
					}
					writeAll(c, ping[:])
				}
				var trigger [1]byte
				io.ReadFull(c, trigger[:])
				payload := bytes.Repeat([]byte("x"), int(binary.BigEndian.Uint32(header[5:])))
				writeAll(c, payload)
				digest := sha256.Sum256(payload)
				if corrupt == "download" {
					digest[0] ^= 255
				}
				writeAll(c, digest[:])
				if corrupt == "download" {
					return
				}
				io.CopyN(io.Discard, c, int64(len(payload)))
				writeAll(c, make([]byte, 40))
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err = runProbe(ctx, e, clientTC, 1024, 1)
			if err == nil || !strings.Contains(err.Error(), corrupt) {
				t.Fatalf("corrupt %s not rejected: %v", corrupt, err)
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("test peer did not exit")
			}
		})
	}
}

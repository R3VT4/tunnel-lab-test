package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Local transport verification bundled in the release binary. No admin or
// public listeners, global service changes, or external server is required.
func selftestCommand(args []string) error {
	if len(args) > 0 {
		return errors.New("selftest takes no arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	checks, err := localChecks(ctx)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"version": version, "passed": true, "platform": runtime.GOOS + "/" + runtime.GOARCH, "scope": "loopback transport checks, not WAN speed or end-to-end deployment health", "checks": checks})
}

func localTCP() (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
func localUDP() (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

func localChecks(ctx context.Context) ([]string, error) {
	dir, err := os.MkdirTemp("", "tunnellab-selftest-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	demo := filepath.Join(dir, "credentials")
	if err = initDemo(demo); err != nil {
		return nil, err
	}
	e, err := loadConfig(filepath.Join(demo, "edge.json"))
	if err != nil {
		return nil, err
	}
	r, err := loadConfig(filepath.Join(demo, "relay.json"))
	if err != nil {
		return nil, err
	}
	if err = validateCredentials(e); err != nil {
		return nil, err
	}
	if err = validateCredentials(r); err != nil {
		return nil, err
	}
	var checks []string
	for _, mode := range []string{"direct", "reverse", "udp", "quic"} {
		if err = localModeCheck(ctx, e, r, mode); err != nil {
			return nil, fmt.Errorf("selftest %s: %w", mode, err)
		}
		checks = append(checks, mode+" payload and authenticated probe")
	}
	return checks, nil
}

func localModeCheck(parent context.Context, e, r Config, mode string) (result error) {
	ctx, cancel := context.WithCancel(parent)
	var closers []io.Closer
	var done []chan error
	defer func() {
		cancel()
		for _, c := range closers {
			c.Close()
		}
		for _, ch := range done {
			select {
			case err := <-ch:
				if result == nil && err != nil {
					result = err
				}
			case <-time.After(3 * time.Second):
				if result == nil {
					result = errors.New("local worker did not stop")
				}
			}
		}
	}()
	start := func(fn func() error) { ch := make(chan error, 1); done = append(done, ch); go func() { ch <- fn() }() }
	newTCP := func() (net.Listener, error) {
		ln, err := localTCP()
		if err == nil {
			closers = append(closers, ln)
		}
		return ln, err
	}
	newUDP := func() (*net.UDPConn, error) {
		c, err := localUDP()
		if err == nil {
			closers = append(closers, c)
		}
		return c, err
	}
	s1, s2 := newStats(), newStats()
	var address string
	var probeConfig Config
	if mode == "udp" {
		target, err := newUDP()
		if err != nil {
			return err
		}
		start(func() error {
			stop := context.AfterFunc(ctx, func() { target.Close() })
			defer stop()
			buffer := make([]byte, 65536)
			for {
				n, a, err := target.ReadFromUDP(buffer)
				if err != nil {
					if ctx.Err() != nil {
						return nil
					}
					return err
				}
				if _, err = target.WriteToUDP(buffer[:n], a); err != nil {
					if ctx.Err() != nil {
						return nil
					}
					return err
				}
			}
		})
		relay, err := newTCP()
		if err != nil {
			return err
		}
		edge, err := newUDP()
		if err != nil {
			return err
		}
		r.Mode = "udp-relay"
		r.Target = target.LocalAddr().String()
		e.Mode = "udp-edge"
		e.Peer = relay.Addr().String()
		rtc, err := tlsConfig(r)
		if err != nil {
			return err
		}
		etc, err := tlsConfig(e)
		if err != nil {
			return err
		}
		start(func() error { return serveUDPRelay(ctx, relay, r, rtc, s1) })
		start(func() error { return serveUDPEdge(ctx, edge, e, etc, s2) })
		address = edge.LocalAddr().String()
		probeConfig = e
	} else {
		target, err := newTCP()
		if err != nil {
			return err
		}
		start(func() error {
			return acceptBounded(ctx, target, 16, func() {}, func(ctx context.Context, c net.Conn) {
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				io.Copy(c, c)
			})
		})
		r.Target = target.Addr().String()
		edge, err := newTCP()
		if err != nil {
			return err
		}
		var relay net.Listener
		if mode == "quic" {
			e.Transport, r.Transport, e.OmitSNI = "quic", "quic", true
			rtc, tlsErr := tlsConfig(r)
			if tlsErr != nil {
				return tlsErr
			}
			relay, err = listenQUIC("127.0.0.1:0", r, rtc)
			if err == nil {
				closers = append(closers, relay)
			}
		} else {
			relay, err = newTCP()
		}
		if err != nil {
			return err
		}
		if mode == "direct" || mode == "quic" {
			e.Peer = relay.Addr().String()
			etc, err := tlsConfig(e)
			if err != nil {
				return err
			}
			rtc, err := tlsConfig(r)
			if err != nil {
				return err
			}
			start(func() error { return serve(ctx, relay, r, rtc, s1) })
			start(func() error { return serve(ctx, edge, e, etc, s2) })
			probeConfig = e
		} else {
			e.Mode = "reverse-edge"
			e.Peer = ""
			e.ServerName = ""
			r.Mode = "reverse-relay"
			r.Peer = relay.Addr().String()
			r.ServerName = "edge.tunnellab.local"
			r.Listen = ""
			etc, err := tlsConfig(e)
			if err != nil {
				return err
			}
			rtc, err := tlsConfig(r)
			if err != nil {
				return err
			}
			start(func() error { return serveReverseEdge(ctx, edge, relay, e, etc, s1) })
			start(func() error { return serveReverseRelay(ctx, r, rtc, s2) })
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for !s2.controlConnected.Load() {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-ticker.C:
				}
			}
			probeConfig = r
		}
		address = edge.Addr().String()
	}
	payload := bytes.Repeat([]byte{0, 255, 1, 128}, 8000)
	if mode == "udp" {
		c, err := net.Dial("udp", address)
		if err != nil {
			return err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		buffer := make([]byte, 65536)
		for _, p := range [][]byte{{}, payload} {
			if _, err = c.Write(p); err != nil {
				return err
			}
			n, err := c.Read(buffer)
			if err != nil {
				return err
			}
			if !bytes.Equal(buffer[:n], p) {
				return errors.New("UDP payload mismatch")
			}
		}
	} else {
		c, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			return err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if err = writeAll(c, payload); err != nil {
			return err
		}
		if err = c.(*net.TCPConn).CloseWrite(); err != nil {
			return err
		}
		got, err := io.ReadAll(c)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, payload) {
			return errors.New("TCP payload mismatch")
		}
	}
	tc, err := tlsConfig(probeConfig)
	if err != nil {
		return err
	}
	_, err = runProbe(ctx, probeConfig, tc, 128*1024, 3)
	return err
}

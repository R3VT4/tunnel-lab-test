package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var version = "0.4.3-alpha"

func main() {
	if err := command(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func command(args []string) error {
	if len(args) == 0 {
		fmt.Println("Tunnel Lab " + version + "\nCommands: init | run | check | service | selftest | status | probe | version\nExamples: check -config demo/edge.json; service list; selftest")
		return nil
	}
	switch args[0] {
	case "version":
		fmt.Println(version)
		return nil
	case "probe":
		return probeCommand(args[1:])
	case "check":
		return checkCommand(args[1:])
	case "service":
		return serviceCommand(args[1:])
	case "selftest":
		return selftestCommand(args[1:])
	case "init":
		f := flag.NewFlagSet("init", flag.ContinueOnError)
		dir := f.String("dir", "demo", "new directory for local test credentials")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := initDemo(*dir); err != nil {
			return err
		}
		fmt.Println("Created local-test configs and credentials in", *dir)
		return nil
	case "status":
		f := flag.NewFlagSet("status", flag.ContinueOnError)
		url := f.String("url", "http://127.0.0.1:9081", "local diagnostics URL")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get(*url + "/api/status")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("status endpoint: %s", resp.Status)
		}
		_, err = io.Copy(os.Stdout, io.LimitReader(resp.Body, 64*1024))
		return err
	case "run":
		f := flag.NewFlagSet("run", flag.ContinueOnError)
		path := f.String("config", "", "JSON configuration path")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		c, err := loadConfig(*path)
		if err != nil {
			return err
		}
		tc, err := tlsConfig(c)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		var ln, tunnel net.Listener
		var udp *net.UDPConn
		if c.Mode == "udp-edge" {
			addr, resolveErr := net.ResolveUDPAddr("udp", c.Listen)
			if resolveErr != nil {
				return resolveErr
			}
			udp, err = net.ListenUDP("udp", addr)
			if err != nil {
				return err
			}
			defer udp.Close()
		}
		if c.Mode != "reverse-relay" && c.Mode != "udp-edge" {
			ln, err = net.Listen("tcp", c.Listen)
			if err != nil {
				return err
			}
			defer ln.Close()
		}
		if c.Mode == "reverse-edge" {
			tunnel, err = net.Listen("tcp", c.TunnelListen)
			if err != nil {
				return err
			}
			defer tunnel.Close()
		}
		admin, err := net.Listen("tcp", c.Admin)
		if err != nil {
			return err
		}
		defer admin.Close()
		s := newStats()
		server := &http.Server{Handler: adminHandler(c, s), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
		adminDone := make(chan error, 1)
		go func() {
			err := server.Serve(admin)
			if err != nil && err != http.ErrServerClosed {
				stop()
			}
			adminDone <- err
		}()
		log.Printf("Tunnel Lab %s mode=%s listen=%s admin=http://%s", version, c.Mode, c.Listen, c.Admin)
		switch c.Mode {
		case "udp-edge":
			err = serveUDPEdge(ctx, udp, c, tc, s)
		case "udp-relay":
			err = serveUDPRelay(ctx, ln, c, tc, s)
		case "reverse-edge":
			err = serveReverseEdge(ctx, ln, tunnel, c, tc, s)
		case "reverse-relay":
			err = serveReverseRelay(ctx, c, tc, s)
		default:
			err = serve(ctx, ln, c, tc, s)
		}
		server.Close()
		adminErr := <-adminDone
		if err != nil {
			return err
		}
		if adminErr != nil && adminErr != http.ErrServerClosed {
			return adminErr
		}
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

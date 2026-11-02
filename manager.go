package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const instanceDirectory = "/etc/tunnellab/instances"

var instanceName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func validateCredentials(c Config) error {
	tc, err := tlsConfig(c)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(tc.Certificates[0].Certificate[0])
	if err != nil {
		return err
	}
	roots := tc.RootCAs
	usage := x509.ExtKeyUsageClientAuth
	if c.Mode == "relay" || c.Mode == "udp-relay" || c.Mode == "reverse-edge" {
		roots = tc.ClientCAs
		usage = x509.ExtKeyUsageServerAuth
	}
	intermediates := x509.NewCertPool()
	for _, der := range tc.Certificates[0].Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		intermediates.AddCert(cert)
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}})
	return err
}
func checkCommand(args []string) error {
	f := flag.NewFlagSet("check", flag.ContinueOnError)
	path := f.String("config", "", "configuration path")
	if err := f.Parse(args); err != nil {
		return err
	}
	c, err := loadConfig(*path)
	if err != nil {
		return err
	}
	if err = validateCredentials(c); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"valid": true, "mode": c.Mode, "scope": "offline configuration, private key pair, certificate trust/expiry/usage; no network test"})
}

type binding struct{ network, host, port string }

func configBindings(c Config) []binding {
	var out []binding
	add := func(network, address string) {
		if address == "" {
			return
		}
		host, port, _ := net.SplitHostPort(address)
		out = append(out, binding{network, host, port})
	}
	add("tcp", c.Admin)
	if c.Mode != "reverse-relay" {
		network := "tcp"
		if c.Mode == "udp-edge" {
			network = "udp"
		}
		add(network, c.Listen)
	}
	if c.Mode == "reverse-edge" {
		add("tcp", c.TunnelListen)
	}
	return out
}
func overlapping(a, b binding) bool {
	if a.network != b.network || a.port != b.port {
		return false
	}
	ipA, ipB := net.ParseIP(a.host), net.ParseIP(b.host)
	return ipA != nil && ipB != nil && (ipA.Equal(ipB) || ipA.IsUnspecified() || ipB.IsUnspecified())
}
func managedConflicts(c Config, others map[string]Config) error {
	bindings := configBindings(c)
	for i, a := range bindings {
		if net.ParseIP(a.host) == nil {
			return errors.New("managed listeners require numeric IP addresses")
		}
		for _, b := range bindings[:i] {
			if overlapping(a, b) {
				return fmt.Errorf("configuration has overlapping %s port %s listeners", a.network, a.port)
			}
		}
		for name, other := range others {
			for _, b := range configBindings(other) {
				if overlapping(a, b) {
					return fmt.Errorf("%s port %s conflicts with managed instance %s", a.network, a.port, name)
				}
			}
		}
	}
	return nil
}
func listInstances(base string) (map[string]Config, error) {
	out := make(map[string]Config)
	entries, err := os.ReadDir(base)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !instanceName.MatchString(entry.Name()) {
			continue
		}
		c, err := loadConfig(filepath.Join(base, entry.Name(), "config.json"))
		if err != nil {
			return nil, fmt.Errorf("instance %s: %w", entry.Name(), err)
		}
		out[entry.Name()] = c
	}
	return out, nil
}

// Copy validated credentials to an independent, private instance directory.
// Existing instances are never overwritten; add does not start any service.
func addInstance(base, name, source string, gid int) error {
	if !instanceName.MatchString(name) {
		return errors.New("name must start with a-z, contain a-z/0-9/hyphen and be at most 32 characters")
	}
	c, err := loadConfig(source)
	if err != nil {
		return err
	}
	if err = validateCredentials(c); err != nil {
		return err
	}
	if err = os.MkdirAll(base, 0750); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(base, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	destination := filepath.Join(base, name)
	if _, err = os.Lstat(destination); err == nil {
		return errors.New("instance already exists; nothing was overwritten")
	} else if !os.IsNotExist(err) {
		return err
	}
	others, err := listInstances(base)
	if err != nil {
		return err
	}
	if err = managedConflicts(c, others); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(base, ".new-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err = os.Chmod(tmp, 0750); err != nil {
		return err
	}
	if gid >= 0 {
		if err = os.Chown(tmp, -1, gid); err != nil {
			return err
		}
	}
	for _, file := range []struct{ source, name string }{{c.CA, "ca.crt"}, {c.Cert, "identity.crt"}, {c.Key, "identity.key"}} {
		data, err := os.ReadFile(file.source)
		if err != nil {
			return err
		}
		path := filepath.Join(tmp, file.name)
		mode := os.FileMode(0600)
		if gid >= 0 {
			mode = 0640
		}
		if err = os.WriteFile(path, data, mode); err != nil {
			return err
		}
		if gid >= 0 {
			if err = os.Chown(path, -1, gid); err != nil {
				return err
			}
		}
	}
	c.CA = "ca.crt"
	c.Cert = "identity.crt"
	c.Key = "identity.key"
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(tmp, "config.json")
	mode := os.FileMode(0600)
	if gid >= 0 {
		mode = 0640
	}
	if err = os.WriteFile(path, append(b, '\n'), mode); err != nil {
		return err
	}
	if gid >= 0 {
		if err = os.Chown(path, -1, gid); err != nil {
			return err
		}
	}
	return os.Rename(tmp, destination)
}

func serviceCommand(args []string) error {
	if len(args) == 0 {
		fmt.Println("service add -name NAME -config FILE | list | start/stop/restart/status/logs -name NAME")
		return nil
	}
	action := args[0]
	f := flag.NewFlagSet("service "+action, flag.ContinueOnError)
	name := f.String("name", "", "instance name")
	var dir, source *string
	if action == "add" || action == "list" {
		dir = f.String("dir", instanceDirectory, "instance directory; custom paths do not control systemd")
	}
	if action == "add" {
		source = f.String("config", "", "source JSON config")
	}
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	switch action {
	case "add":
		gid := -1
		if filepath.Clean(*dir) == instanceDirectory {
			if os.Geteuid() != 0 {
				return errors.New("service add to /etc requires sudo")
			}
			group, err := user.LookupGroup("tunnellab")
			if err != nil {
				return errors.New("install the service account first with scripts/install.sh")
			}
			gid, err = strconv.Atoi(group.Gid)
			if err != nil {
				return err
			}
		}
		if err := addInstance(*dir, *name, *source, gid); err != nil {
			return err
		}
		fmt.Println("Added", *name, "without starting it. Configuration:", filepath.Join(*dir, *name, "config.json"))
		return nil
	case "list":
		instances, err := listInstances(*dir)
		if err != nil {
			return err
		}
		rows := make(map[string]any)
		for name, c := range instances {
			rows[name] = map[string]string{"mode": c.Mode, "listen": c.Listen, "admin": c.Admin}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	case "start", "stop", "restart", "status", "logs":
		if !instanceName.MatchString(*name) {
			return errors.New("invalid instance name")
		}
		if _, err := os.Stat(filepath.Join(instanceDirectory, *name, "config.json")); err != nil {
			return err
		}
		unit := "tunnellab@" + *name + ".service"
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		var cmd *exec.Cmd
		if action == "logs" {
			cmd = exec.CommandContext(ctx, "journalctl", "--unit", unit, "--lines", "100", "--no-pager")
		} else {
			arguments := []string{action, unit}
			if action == "start" {
				arguments = []string{"enable", "--now", unit}
			}
			if action == "stop" {
				arguments = []string{"disable", "--now", unit}
			}
			if action == "status" {
				arguments = append(arguments, "--no-pager")
			}
			cmd = exec.CommandContext(ctx, "systemctl", arguments...)
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	default:
		return fmt.Errorf("unknown service action %q", strings.TrimSpace(action))
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestManagedFileModesSurviveRestrictiveUmask(t *testing.T) {
	if os.Getenv("TUNNELLAB_PERMISSION_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestManagedFileModesSurviveRestrictiveUmask$")
		cmd.Env = append(os.Environ(), "TUNNELLAB_PERMISSION_CHILD=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("umask regression failed: %v\n%s", err, output)
		}
		return
	}
	// Change umask only in this isolated process, never alongside other tests.
	syscall.Umask(0077)
	e, _ := testConfigs(t)
	for _, gid := range []int{-1, os.Getgid()} {
		base := filepath.Join(t.TempDir(), "instances")
		if err := addInstance(base, "test", configFile(t, e), gid); err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if gid >= 0 {
			want = 0640
		}
		for _, name := range []string{"config.json", "ca.crt", "identity.crt", "identity.key"} {
			info, err := os.Stat(filepath.Join(base, "test", name))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != want {
				t.Fatalf("%s mode %o, want %o", name, info.Mode().Perm(), want)
			}
			if gid >= 0 && int(info.Sys().(*syscall.Stat_t).Gid) != gid {
				t.Fatal("wrong service group")
			}
		}
	}
}

func configFile(t *testing.T, c Config) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "source.json")
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestManagedInstanceIndependentCredentialsAndNoOverwrite(t *testing.T) {
	e, _ := testConfigs(t)
	source := configFile(t, e)
	base := filepath.Join(t.TempDir(), "instances")
	if err := addInstance(base, "edge-one", source, -1); err != nil {
		t.Fatal(err)
	}
	managed, err := loadConfig(filepath.Join(base, "edge-one", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = validateCredentials(managed); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{e.CA, managed.CA}, {e.Cert, managed.Cert}, {e.Key, managed.Key}} {
		before, err := os.ReadFile(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) || pair[0] == pair[1] {
			t.Fatal("credentials not independently copied")
		}
	}
	keyBefore, _ := os.ReadFile(managed.Key)
	if err = addInstance(base, "edge-one", source, -1); err == nil {
		t.Fatal("duplicate instance overwritten")
	}
	keyAfter, _ := os.ReadFile(managed.Key)
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("existing key changed")
	}
	info, err := os.Stat(managed.Key)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private key permissions incorrect")
	}
}

func TestManagedConflictAndProtocolSeparation(t *testing.T) {
	e, _ := testConfigs(t)
	base := filepath.Join(t.TempDir(), "instances")
	if err := addInstance(base, "tcp-one", configFile(t, e), -1); err != nil {
		t.Fatal(err)
	}
	e.Admin = "127.0.0.1:9181"
	e.Listen = "0.0.0.0:8080"
	if err := addInstance(base, "wildcard", configFile(t, e), -1); err == nil {
		t.Fatal("overlapping wildcard listener accepted")
	}
	e.Mode = "udp-edge"
	e.Listen = "127.0.0.1:8080"
	if err := addInstance(base, "udp-one", configFile(t, e), -1); err != nil {
		t.Fatal("UDP and TCP may share a numeric port", err)
	}
	instances, err := listInstances(base)
	if err != nil || len(instances) != 2 {
		t.Fatal("bad instance list", err)
	}
}

func TestManagedRejectsBadNamesAndUntrustedCredentials(t *testing.T) {
	e, _ := testConfigs(t)
	base := filepath.Join(t.TempDir(), "instances")
	source := configFile(t, e)
	for _, name := range []string{"../escape", "-option", "a/b", "Name", "bad name", ""} {
		if err := addInstance(base, name, source, -1); err == nil {
			t.Fatalf("invalid name accepted %q", name)
		}
	}
	other, _ := testConfigs(t)
	e.CA = other.CA
	if err := addInstance(base, "untrusted", configFile(t, e), -1); err == nil {
		t.Fatal("untrusted identity accepted")
	}
	if _, err := os.Stat(base); !os.IsNotExist(err) {
		t.Fatal("invalid input left a directory behind")
	}
}

func TestManagedConcurrentAddsCannotClaimSamePorts(t *testing.T) {
	e, _ := testConfigs(t)
	source := configFile(t, e)
	base := filepath.Join(t.TempDir(), "instances")
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, name := range []string{"first", "second"} {
		wg.Go(func() { results <- addInstance(base, name, source, -1) })
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("expected one port owner, got %d", success)
	}
}

func TestBuiltinLocalChecks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	checks, err := localChecks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 4 {
		t.Fatal("incomplete built-in test")
	}
}

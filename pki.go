package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return n
}

// initDemo creates a private trust group with one relay and one edge identity.
// CA signing key exists in memory only; this alpha does not implement renewal.
func initDemo(dir string) error {
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(dir)
		}
	}()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Tunnel Lab private CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		return err
	}
	for _, role := range []string{"edge", "relay"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		leaf := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: role}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(0, 0, 90), KeyUsage: x509.KeyUsageDigitalSignature}
		leaf.DNSNames = []string{role + ".tunnellab.local"}
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(dir, role+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			return err
		}
		kb, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(dir, role+".key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0600); err != nil {
			return err
		}
		c := Config{Mode: role, Listen: "127.0.0.1:8080", CA: "ca.crt", Cert: role + ".crt", Key: role + ".key", Admin: "127.0.0.1:9081", MaxConnections: 256, IdleSeconds: 120}
		if role == "relay" {
			c.Listen = "127.0.0.1:7443"
			c.Target = "127.0.0.1:9000"
			c.Admin = "127.0.0.1:9082"
		} else {
			c.Peer = "127.0.0.1:7443"
			c.ServerName = "relay.tunnellab.local"
		}
		b, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			return err
		}
		if len(b) == 0 {
			return errors.New("empty config")
		}
		if err = os.WriteFile(filepath.Join(dir, role+".json"), append(b, '\n'), 0600); err != nil {
			return err
		}
		c.Mode = "reverse-" + role
		if role == "edge" {
			c.Peer = ""
			c.ServerName = ""
			c.TunnelListen = "127.0.0.1:7444"
		} else {
			c.Listen = ""
			c.Peer = "127.0.0.1:7444"
			c.ServerName = "edge.tunnellab.local"
		}
		b, err = json.MarshalIndent(c, "", "  ")
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(dir, "reverse-"+role+".json"), append(b, '\n'), 0600); err != nil {
			return err
		}
		c.Mode = "udp-" + role
		c.TunnelListen = ""
		c.UDPQueuePackets = 8
		if role == "edge" {
			c.Listen = "127.0.0.1:8081"
			c.Peer = "127.0.0.1:7445"
			c.ServerName = "relay.tunnellab.local"
		} else {
			c.Listen = "127.0.0.1:7445"
			c.Peer = ""
			c.ServerName = ""
			c.Target = "127.0.0.1:9001"
		}
		b, err = json.MarshalIndent(c, "", "  ")
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(dir, "udp-"+role+".json"), append(b, '\n'), 0600); err != nil {
			return err
		}
	}
	ok = true
	return nil
}

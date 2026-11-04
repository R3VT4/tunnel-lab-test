package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"math"
	"net"
	"os"
	"time"
)

const probeALPN = "tunnellab-probe/0.3"
const maxProbeBytes = 16 * 1024 * 1024

type ProbeReport struct {
	Version            string   `json:"version"`
	Transport          string   `json:"transport"`
	Scope              string   `json:"scope"`
	PacketLossMeasured bool     `json:"packet_loss_measured"`
	SetupMS            float64  `json:"tcp_tls_setup_ms,omitempty"`
	QUICSetupMS        *float64 `json:"quic_setup_ms,omitempty"`
	RTTMinMS           float64  `json:"application_rtt_min_ms"`
	RTTMeanMS          float64  `json:"application_rtt_mean_ms"`
	RTTMaxMS           float64  `json:"application_rtt_max_ms"`
	RTTStddevMS        float64  `json:"application_rtt_stddev_ms"`
	Rounds             int      `json:"rounds"`
	BytesEachWay       int      `json:"bytes_each_way"`
	DownloadMbps       float64  `json:"download_goodput_mbps"`
	UploadMbps         float64  `json:"upload_confirmed_goodput_mbps"`
}

// Probe is authenticated on the existing TLS listener and bounded to 32 MiB
// of transfer (16 MiB each way) and a 30-second connection deadline.
func handleProbe(ctx context.Context, conn net.Conn) error {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	var header [9]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	rounds := int(header[4])
	size := int(binary.BigEndian.Uint32(header[5:]))
	if string(header[:4]) != "TLP1" || rounds < 1 || rounds > 32 || size < 1024 || size > maxProbeBytes {
		return errors.New("invalid probe request")
	}
	var ping [16]byte
	for range rounds {
		if _, err := io.ReadFull(conn, ping[:]); err != nil {
			return err
		}
		if err := writeAll(conn, ping[:]); err != nil {
			return err
		}
	}
	var trigger [1]byte
	if _, err := io.ReadFull(conn, trigger[:]); err != nil {
		return err
	}
	if trigger[0] != 'D' {
		return errors.New("invalid download trigger")
	}
	block := make([]byte, 32*1024)
	if _, err := rand.Read(block); err != nil {
		return err
	}
	hash := sha256.New()
	for remaining := size; remaining > 0; {
		n := min(len(block), remaining)
		if err := writeAll(conn, block[:n]); err != nil {
			return err
		}
		hash.Write(block[:n])
		remaining -= n
	}
	if err := writeAll(conn, hash.Sum(nil)); err != nil {
		return err
	}
	hash.Reset()
	n, err := io.CopyN(hash, conn, int64(size))
	if err != nil {
		return err
	}
	var receipt [40]byte
	binary.BigEndian.PutUint64(receipt[:8], uint64(n))
	copy(receipt[8:], hash.Sum(nil))
	return writeAll(conn, receipt[:])
}

func runProbe(ctx context.Context, c Config, tc *tls.Config, size, rounds int) (ProbeReport, error) {
	report := ProbeReport{Version: version, Transport: "tcp/tls1.3", Scope: "authenticated_peer_only; single-stream application goodput", Rounds: rounds, BytesEachWay: size}
	if rounds < 1 || rounds > 32 || size < 1024 || size > maxProbeBytes {
		return report, errors.New("rounds must be 1..32 and bytes 1024..16777216")
	}
	if c.Peer == "" || c.ServerName == "" {
		return report, errors.New("probe requires an edge, udp-edge or reverse-relay config")
	}
	start := time.Now()
	var conn net.Conn
	var err error
	if c.Transport == "quic" {
		pool := &quicPool{config: c, tls: tc}
		defer pool.Close()
		conn, err = pool.Open(ctx, probeALPN)
		report.Transport = "quic/udp/tls1.3"
	} else {
		conn, err = dialTransport(ctx, c, tc, probeALPN)
	}
	if err != nil {
		return report, err
	}
	defer conn.Close()
	report.SetupMS = float64(time.Since(start)) / float64(time.Millisecond)
	if c.Transport == "quic" {
		value := report.SetupMS
		report.QUICSetupMS = &value
		report.SetupMS = 0
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if t, ok := conn.(*tls.Conn); ok && c.ProtocolNegotiation != "encrypted-preface" && t.ConnectionState().NegotiatedProtocol != probeALPN {
		return report, errors.New("peer does not support probe")
	}
	var header [9]byte
	copy(header[:4], "TLP1")
	header[4] = byte(rounds)
	binary.BigEndian.PutUint32(header[5:], uint32(size))
	if err = writeAll(conn, header[:]); err != nil {
		return report, err
	}
	times := make([]float64, 0, rounds)
	for range rounds {
		var request, response [16]byte
		rand.Read(request[:])
		start = time.Now()
		if err = writeAll(conn, request[:]); err != nil {
			return report, err
		}
		if _, err = io.ReadFull(conn, response[:]); err != nil {
			return report, err
		}
		if request != response {
			return report, errors.New("probe echo mismatch")
		}
		times = append(times, float64(time.Since(start))/float64(time.Millisecond))
	}
	report.RTTMinMS = times[0]
	for _, v := range times {
		report.RTTMinMS = math.Min(report.RTTMinMS, v)
		report.RTTMaxMS = math.Max(report.RTTMaxMS, v)
		report.RTTMeanMS += v
	}
	report.RTTMeanMS /= float64(rounds)
	for _, v := range times {
		report.RTTStddevMS += (v - report.RTTMeanMS) * (v - report.RTTMeanMS)
	}
	report.RTTStddevMS = math.Sqrt(report.RTTStddevMS / float64(rounds))
	hash := sha256.New()
	start = time.Now()
	if err = writeAll(conn, []byte{'D'}); err != nil {
		return report, err
	}
	if _, err = io.CopyN(hash, conn, int64(size)); err != nil {
		return report, err
	}
	var digest [32]byte
	if _, err = io.ReadFull(conn, digest[:]); err != nil {
		return report, err
	}
	if !bytes.Equal(digest[:], hash.Sum(nil)) {
		return report, errors.New("download checksum mismatch")
	}
	report.DownloadMbps = float64(size) * 8 / time.Since(start).Seconds() / 1e6
	block := make([]byte, 32*1024)
	rand.Read(block)
	hash.Reset()
	start = time.Now()
	for remaining := size; remaining > 0; {
		n := min(len(block), remaining)
		if err = writeAll(conn, block[:n]); err != nil {
			return report, err
		}
		hash.Write(block[:n])
		remaining -= n
	}
	var receipt [40]byte
	if _, err = io.ReadFull(conn, receipt[:]); err != nil {
		return report, err
	}
	if binary.BigEndian.Uint64(receipt[:8]) != uint64(size) || !bytes.Equal(receipt[8:], hash.Sum(nil)) {
		return report, errors.New("upload receipt mismatch")
	}
	report.UploadMbps = float64(size) * 8 / time.Since(start).Seconds() / 1e6
	return report, nil
}

func probeCommand(args []string) error {
	f := flag.NewFlagSet("probe", flag.ContinueOnError)
	path := f.String("config", "", "client-side JSON config")
	size := f.Int("bytes", 1024*1024, "bytes each way (1024..16777216)")
	rounds := f.Int("rounds", 8, "RTT samples (1..32)")
	if err := f.Parse(args); err != nil {
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
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	report, err := runProbe(ctx, c, tc, *size, *rounds)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

# Tunnel Lab

**Working name. v0.5.0-alpha — experimental Direct TCP streams over QUIC/UDP.**

[راهنمای فارسی](README_FA.md) · [نصب و آماده‌سازی GitHub](INSTALL_FA.md) · [Validation](VALIDATION.md)

A small Linux tunnel project with direct/reverse TCP forwarding, direct
UDP-over-TLS, mutual TLS authentication, a read-only local status page, and
an authenticated peer-measurement command. The aim is useful operation and
measurable behavior, with further transport and path-management work to follow.

UDP is framed inside TCP/TLS: this is not native UDP or QUIC. TCP head-of-line
blocking applies. Reverse UDP and data-session migration are not implemented.
There is no claim of better WAN performance than other tunnel tools.

## Source-only ZIP

`tunnel-lab-0.4.0-source.zip` contains only source and documentation. It excludes
bin/ and dist/. On Windows follow [PUSH_TO_GITHUB_FA.md](PUSH_TO_GITHUB_FA.md) to
upload the source and let GitHub Actions build the Linux executables. The binary
commands below apply to a built executable, a release archive or the full test bundle.

## Test without servers

From the source bundle on Linux amd64:

```bash
chmod +x bin/tunnellab-linux-amd64
bin/tunnellab-linux-amd64 selftest
```

From an extracted release archive:

```bash
./tunnellab selftest
```

The built-in test uses only temporary credentials and loopback listeners. It
checks direct TCP, reverse TCP, UDP datagrams and authenticated peer measurements.
It does not install a service, measure Internet speed, or validate a real deployment.

## Build

Use a maintained Go 1.26 patch release or newer compatible toolchain:

```bash
go test -race -count=1 -timeout 90s ./...
go vet ./...
CGO_ENABLED=0 go build -buildvcs=false -trimpath -o tunnellab .
./tunnellab selftest
```

The QUIC transport uses pinned quic-go and Go x/ dependencies (see THIRD_PARTY_NOTICES.md). Production readiness,
long-running behavior and real network performance remain to be established.

## Install and manage

Read [INSTALL_FA.md](INSTALL_FA.md) for the complete paired-server procedure.
The installer requires Linux with systemd and creates a dedicated service account.
It starts no instances automatically.

```bash
sudo bash scripts/install.sh --binary ./tunnellab
./tunnellab init -dir demo
./tunnellab check -config demo/edge.json
sudo tunnellab service add -name edge-one -config demo/edge.json
sudo tunnellab service start -name edge-one
sudo tunnellab service list
sudo tunnellab service status -name edge-one
sudo tunnellab service logs -name edge-one
sudo tunnellab service stop -name edge-one
```

Edit and distribute the paired configuration before starting a real deployment.
Each instance has its own credentials and configuration. The manager checks
configured listener conflicts; ports held by unrelated software are detected
when the service binds at startup. Start enables autostart; stop disables it.
The web page remains read-only and loopback-only.

## GitHub source and releases

Put this directory's **contents** at the repository root; uploading a ZIP alone
does not create a buildable source tree. Do not upload runtime private keys,
credentials, or your generated `demo/` directory.

- The Checks workflow runs tests, executable self-tests, isolated installation
  checks and packaging on pushes and pull requests.
- A version tag such as `v0.4.0-alpha` starts the Draft release workflow.
- That workflow checks the source and builds Linux amd64/arm64 archives plus
  SHA-256 checksums. It creates a **draft prerelease**, which the owner reviews
  and publishes. The workflow has been prepared, not run on a GitHub runner here.
- `VERSION` must match the pushed tag. To build archives locally:

```bash
bash scripts/build-release.sh
```

No repository URL, owner, or final project name is hard-coded.
See [CHANGELOG.md](CHANGELOG.md) for the release scope and [VALIDATION.md](VALIDATION.md)
for the actual checks and their limits.

## Protocol negotiation compatibility

The default remains ALPN for compatibility with v0.4.0-alpha. To omit the
application protocol from the TLS ClientHello, install v0.4.1-alpha on BOTH
servers and set this field in BOTH active instance configurations:

```json
"protocol_negotiation": "encrypted-preface"
```

The peers still use TLS 1.3, a private trusted CA, server hostname verification,
and required client certificates. After TLS authentication, the client sends
`TLAB`, version byte `1`, and a protocol-kind byte inside the encrypted stream;
the server validates the requested kind and echoes the six-byte header before
application data. Direct TCP, reverse control/data, UDP-over-TLS, and probes use
the same negotiation mechanism. Invalid, unsupported, truncated, and mismatched
negotiations fail closed. No automatic downgrade or plaintext fallback occurs.
This is not an HTTP implementation, browser impersonation, or a guarantee that
any particular network will permit the connection. SNI is unchanged.

`probe` now identifies TCP-connect, TLS-handshake and encrypted-negotiation
failures separately. Servers log TLS/negotiation failures, and reverse relays
log control-session failures. Logs do not include credentials or data tickets.

For an existing managed instance, edit `/etc/tunnellab/instances/NAME/config.json`
and restart that instance. Editing the original imported JSON does not update
its independent managed copy. A binary upgrade alone does not enable this mode.

## Sending SNI separately from verifying identity

Client configurations (`edge`, `udp-edge`, `reverse-relay`) may additionally use:

```json
"protocol_negotiation": "encrypted-preface",
"omit_sni": true
```

Keep `server_name` set to the expected certificate DNS name. `omit_sni` only
removes that identity from ClientHello. Go's coupled SNI/default verification is
replaced by a mandatory `VerifyConnection` callback that checks the entire
certificate chain against the configured CA, certificate signatures and
validity, the expected DNS name, and ServerAuth usage. It never accepts an
unverified certificate. Server-side mutual client certificate verification is
unchanged. Server configurations reject `omit_sni: true` to catch role mistakes.
The default remains `false`. The encrypted wire format is unchanged from
0.4.1-alpha, so a 0.4.2 client can use an already-updated 0.4.1 server configured
for encrypted-preface. Only the client needs this update for that pairing.

Deployment evidence: in a consecutive OpenSSL comparison without ALPN and with
X25519, the no-SNI handshake succeeded with certificate verification and the
SNI-on handshake timed out. This does not establish where or why the traffic
was interrupted, or establish successful application forwarding by this update.

## Direct connection diagnostics (0.4.3-alpha)

The loopback status API now includes the configured connection/idle limits and,
for `edge`/`relay`, `connection_diagnostics`. This separates setup, forwarding,
probe and half-closed active connections, records peak concurrency, and exposes
setup failures by TCP/TLS/protocol/target stage. Half-closed connections remain
a subset of forwarding connections. A bounded eight-event history and last
error contain fixed categories and UTC timestamps, never raw error strings,
credentials, addresses or tickets.

Direct idle expiry is now counted in `idle_timeouts`, not legacy `errors`.
Peer resets/broken pipes and other I/O failures remain errors with separate
counters. Process-context cancellation is counted separately for bridges.
Reverse/UDP error semantics remain unchanged and their status omits this
Direct-only object. Do not compare raw error totals across versions as if their
semantics were identical. Snapshots of live atomic gauges can briefly differ
while a connection changes phase; no transactional snapshot is claimed.

The transfer code preserves half-close, serializes idle deadline refreshes and
closes the Direct relay's TLS wrapper before the raw socket. No connection cap,
idle default, authentication rule or wire protocol changes in this release.
Local tests do not establish the cause of the user's earlier WAN interruption
or promise more throughput. See DIAGNOSTICS_FA.md and ROADMAP_FA.md.


## Direct operation attribution (0.4.4-alpha)

Transfer events now include fixed `side`, `operation` and `error_code` values.
The edge names its input `client` and its TLS connection `tunnel`; the relay
names its TLS input `tunnel` and configured destination `target`. Operations
are `read`, `write` and `close_write`. `transfer_failure_counts` retains a
cumulative breakdown (including peer disconnects), excluding idle and shutdown.
Only the first observed terminating copy error is reported. These fields do
not establish a remote root cause or imply that CloseWrite failures are harmless.
Raw error strings, addresses and payloads are excluded. See DIAGNOSTICS_FA.md.


## Direct half-close recovery (0.4.5-alpha)

After clean EOF, plain-socket CloseWrite ENOTCONN no longer aborts the opposite
copy. The bridge still waits for its EOF, error, shared idle deadline or process
cancellation. `half_close_already_closed` records the handled condition; it does
not imply a successful stream. TLS CloseWrite and read/write errors remain
failures. Reverse/UDP are unchanged. See DIAGNOSTICS_FA.md for counter semantics.


## Experimental QUIC transport (0.5.0-alpha)

Set `transport: "quic"` only on a separate Direct edge/relay pair. Edge accepts
TCP user connections; relay listens on UDP. Each user flow gets a bidirectional
stream on a reused, mutually authenticated QUIC session. The dedicated ALPN is
`tunnellab-quic/0.1`; `encrypted-preface` is TCP-only and rejected for QUIC.
Client-only omit_sni retains full hostname verification. QUIC is not HTTP/3 or
traffic camouflage. Native UDP payloads and QUIC Reverse are not implemented.

Existing configs default to TCP. Create new managed instances/ports for WAN
comparison instead of changing the working pair. A dead session is replaced
for a new flow; active streams are not replayed or migrated by Tunnel Lab.
0-RTT, DATAGRAM and incoming unidirectional streams are disabled. Sessions and
streams have separate bounds; see QUIC_FA.md for exact limits and deployment.
`selftest` includes QUIC; `probe` reports `quic/udp/tls1.3` and `quic_setup_ms`.
This experimental transport has passed local tests, not the user's WAN route.

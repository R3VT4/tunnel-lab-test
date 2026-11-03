# Tunnel Lab

**Working name. v0.4.1-alpha — encrypted protocol negotiation for deployment testing.**

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

The application has no third-party Go dependencies. Production readiness,
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

# v0.4.2-alpha

- Add client-only `omit_sni: true`, retaining `server_name` as the required
  certificate identity. Full x509 chain, hostname, validity and ServerAuth
  checks are enforced by a mandatory VerifyConnection callback.
- Preserve required client certificates on servers and the encrypted-preface
  wire format introduced in 0.4.1. An encrypted-preface 0.4.1 server does not
  need replacement to accept an updated 0.4.2 client.
- Add ClientHello observation to verify SNI omission, certificate validity and
  usage checks, and run direct/reverse/UDP and probe tests with SNI omitted.
- WAN status: the user reported success without SNI and a timeout with SNI
  in consecutive no-ALPN OpenSSL tests. This update still needs a WAN test.

# v0.4.1-alpha

- Add opt-in `protocol_negotiation: encrypted-preface` on both peers. TLS 1.3
  and mutual certificate authentication remain required; the protocol is chosen
  by a bounded six-byte exchange after TLS instead of public ALPN.
- Retain the default ALPN wire format for existing 0.4.0 deployments.
- Report TCP connection, TLS handshake and encrypted negotiation failures
  separately; log server handshake/negotiation and reverse control errors.
- Add direct/reverse/UDP payload and authenticated-probe coverage for the new
  mode, invalid/cross-protocol prefaces, incompatible profiles, certificate
  verification and handshake timeout cleanup.
- WAN status: a user-reported OpenSSL TLS handshake succeeded without custom
  ALPN after earlier custom-ALPN attempts timed out. This narrows the diagnosis;
  the updated tunnel itself has not yet been verified on that WAN route.

# 0.4.0-alpha

- Add built-in loopback selftest without Go, Python or external servers.
- Add offline check for configuration, matching private key and certificate trust/expiry/usage.
- Add separate named instances with copied private credentials and no-overwrite imports.
- Reject overlapping configured listeners, including conservative wildcard checks.
- Serialize concurrent imports so they cannot independently claim the same ports.
- Add CLI service list, start, stop, restart, status and logs.
- Add Linux systemd installer, dedicated service identity and per-instance unit.
- Add isolated staging installation that makes no global account/service changes.
- Prepare GitHub checks and tag-triggered draft prerelease workflows.
- Add Linux amd64/arm64 release build script, checksums and Persian installation guide.

Start enables automatic startup; stop disables it. Web management remains read-only.
Real systemd startup and the GitHub workflows still require deployment testing.
No repository has been published from this environment; the working name is provisional.

# 0.3.0-alpha

- Add direct udp-edge/udp-relay modes with datagram framing over mutual TLS.
- Preserve zero-length and binary datagrams up to 65507 bytes.
- Isolate each UDP source in a separate stream and connected target UDP socket.
- Bound associations, queued packet count and queued payload bytes; expire idle sessions.
- Expose datagram counters and known local drops separately from network loss.
- Add authenticated probe command on existing server listeners with separate ALPN.
- Measure TCP/TLS setup, application RTT and single-stream confirmed goodput.
- Verify download hashes and upload byte-count/hash receipts; cap request volume and time.
- Add local UDP binary smoke test and extend all binary smoke modes with probe checks.
- Working name remains provisional. No WAN performance claim is made.

UDP here is UDP-over-TCP/TLS; head-of-line blocking applies. Native UDP and reverse
UDP are future work. Probe never claims to measure packet loss or target health.
Credentials from 0.2 can be reused; run init into a fresh directory to obtain all
six example configs without overwriting existing credentials.

# 0.2.0-alpha

- Add reverse-edge and reverse-relay modes over mutually authenticated TLS 1.3.
- Separate control connections from independently authenticated data connections.
- Add single-use random data tickets tied to the control peer certificate.
- Add heartbeat checks and bounded exponential reconnect delay with jitter.
- Keep established data connections alive when only the control connection fails.
- Enforce connection/pending limits and clean pending requests on control loss.
- Generate direct and reverse example configurations from one private trust group.
- Show reverse control state, reconnect attempts and pending requests in local status.
- Extend automatic binary smoke tests to reverse mode without external servers.
- Keep the working name provisional and remove unrelated README references.

## Upgrade from 0.1

Direct mode wire ALPN is unchanged. Reverse mode uses a separate ALPN.
Reverse mode requires credentials generated with 0.2 (or equivalent manually
issued certificates with the appropriate identity and server/client usages).
Run init into a new directory and coordinate both sides; do not overwrite keys.

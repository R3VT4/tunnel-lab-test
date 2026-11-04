# v0.4.5-alpha

- On Direct plain-socket CloseWrite returning ENOTCONN after clean copy EOF,
  keep draining the opposite direction instead of immediately closing both
  sockets. Retain the normal shared idle deadline and process cancellation.
- Record half_close_already_closed separately, with a bounded non-failure event.
  This counter reports a handled half-close condition, not successful delivery;
  completed is incremented only if both copy directions subsequently finish.
- Actual read/write ENOTCONN, reset, other CloseWrite errors and TLS CloseWrite
  errors remain failures. Reverse/UDP behavior is unchanged. This does not prove
  that historical WAN sessions lost payloads or that every such event is benign.
- Add a delayed-response regression that fails on 0.4.4 behavior and boundary
  checks for subsequent reset, idle, shutdown and unchanged legacy behavior.
- No wire, configuration, authentication or limit changes. WAN check pending.

# v0.4.4-alpha

- Attribute Direct bridge failures to client/tunnel/target and read/write/close_write.
  Preserve the first observed terminating copy failure and errors.Is/As behavior;
  do not substitute secondary failures caused by bridge cleanup.
- Include fixed symbolic error codes and a cumulative transfer_failure_counts
  breakdown in bounded status events. Raw errors, payloads and addresses are
  excluded. Existing error categories and limits are retained, including failures
  reported by CloseWrite; no historical WAN error is declared harmless.
- Keep clean EOF unwrapped for io.Copy and preserve short-write detection,
  half-close responses, cancellation and idle behavior. The read-only page
  displays the additional last-error fields when present.
- Add fault-injection attribution and safe-code tests. No wire protocol,
  authentication, configuration or transport additions. WAN validation pending.

# v0.4.3-alpha

- Instrument Direct TCP setup/forwarding/probe/half-close phases, peak active
  connections, per-stage setup failures and bounded categorized event history.
- Separate Direct idle expiration and process shutdown from transfer failures;
  retain reset/broken-pipe and other I/O errors in separate counters.
- Serialize shared idle deadline updates and close the Direct relay TLS wrapper
  before its underlying raw socket. Preserve half-close response behavior.
- Display capacity/phase counters and the actual running version on the
  read-only status page. No wire, authentication, default-limit or idle-policy
  change. Reverse/UDP do not yet expose the new Direct-only diagnostics.
- Add fault-based tests for failed-handshake slot reuse, delayed half-close
  responses, idle TLS close notification, reset/shutdown classification and
  bounded safe event reporting. WAN deployment remains pending.
- Document staged QUIC/UDP and HTTP/2 transport plans; those transports are not
  implemented by this release.

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

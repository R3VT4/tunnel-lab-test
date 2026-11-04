# Validation — 0.4.0-alpha

Date: 2026-11-02. Runtime: Go 1.26.10, Linux amd64.

## Completed checks

- `go test -race -count=1 -timeout 60s -v ./...`: 28 top-level tests passed, including the race detector; no data race reported.
- `go vet ./...`: passed.
- Linux amd64 binary built with `go build -buildvcs=false -trimpath`.
- `python3 scripts/smoke.py`: passed against the compiled binary in direct mode.
- `python3 scripts/smoke.py --reverse`: passed against the compiled binary in
  reverse mode, including initial retry while the edge process starts.
- Both binary tests use real loopback TCP sockets, temporary private credentials
  and a local HTTP target. Responses are compared byte-for-byte; both live status
  APIs and the Persian HTML endpoint are checked. Processes exit on SIGTERM.
- `python3 scripts/udp_smoke.py`: compiled UDP edge/relay, zero-length, binary and
  65507-byte datagrams, live counters and a real authenticated probe passed.
- All three binary smoke modes also execute the probe CLI and validate its JSON output.
- Status-page JavaScript syntax checked with `node --check`.
- Built-in `selftest` passed on the Linux amd64 executable.
- `scripts/install_smoke.py` passed using a disposable installation root; global
  account/systemd commands were replaced with failing sentinels and were not invoked.
- Shell installer and release-builder syntax checked with `bash -n`.
- systemd-analyze verified a temporary copy of the template with only the executable
  path changed to the local test binary; this is a static check, not service activation.
- GitHub CI and draft-release workflows have been prepared; no GitHub-hosted run
  or publication has been performed in this environment.

## Test coverage

1. Six concurrent direct TCP transfers over mTLS; binary payloads, request
   half-close, response and exact data byte counters.
2. Rejection of a client without a certificate.
3. Rejection of an untrusted CA or incorrect server identity.
4. Connection cap and shutdown during an incomplete TLS handshake.
5. Idle data connection timeout.
6. Admin read-only methods and loopback Host enforcement.
7. Rejection of invalid configuration.
8. Credential initialization refuses to overwrite an existing directory.
9. Six concurrent reverse transfers, binary payloads and TCP half-close.
10. Forced control-channel closure during an established stream: data continues,
    control reconnects, and a fresh user connection succeeds.
11. Relay starts before edge is available, retries and subsequently transfers data.
12. Unknown and consumed data tickets are rejected without damaging the live stream.
13. Wrong certificate role and simultaneous duplicate control are rejected.
14. Control-frame size bounds and preservation of subsequent raw payload bytes.
15. Pending request capacity and cleanup after control loss.
16. An idle control session survives beyond its 15-second read timeout through
    actual heartbeat exchanges, without replacement or reconnect.

17. UDP datagram boundaries, zero-byte and maximum-size datagrams.
18. Six concurrent UDP sources with 12 requests each remain isolated.
19. UDP association capacity and creation of a new association after idle expiry.
20. Queue byte/packet bounds, cleanup, oversized and truncated datagram frames.
21. Authenticated probe on direct TCP, UDP relay and reverse listeners.
22. Probe transfer bounds, server rejection of excessive volume, and untrusted peer.
23. Valid TLS peers returning a corrupted download digest or upload receipt are rejected.

24. Managed instance imports independent credential copies and does not overwrite existing instances.
25. Conflicting wildcard listeners are rejected; UDP and TCP numeric-port sharing is allowed.
26. Invalid instance names and untrusted credentials leave no installed instance.
27. Concurrent additions cannot claim the same configured ports.
28. Built-in local checks exercise all three transport modes and peer measurements.

## Not established

- systemd units have not been activated on a booted host here. A staged file
  installation does not establish service-account behavior, startup at boot or
  compatibility with every distribution. Those require the deployment test.
- No WAN throughput benchmark, Iran/international route test, sustained load or
  comparative performance result. Local test success is not a bandwidth claim.
- No independent security audit, long-running fuzz campaign or certificate
  lifecycle testing. The application's authorization and framing need broader review.
- HTML and API were tested over HTTP. Chromium is unavailable in this environment;
  desktop/mobile appearance has not been visually verified in a browser.
- UDP is carried inside a TCP/TLS stream with per-source framing. Native UDP transport,
  reverse UDP, QUIC, TUN, multipath and data-session resumption are not implemented.
- Probe RTT is at the application layer, and goodput includes protocol processing.
  It tests the authenticated peer, not the ultimate target, and does not measure packet loss.

The admin interface remains loopback-only and read-only. Control-channel liveness
is reported separately and does not prove that the target service is reachable.
This release is a lab alpha for one paired edge/relay trust group.


## Release packaging

The build script cross-compiles static Linux amd64 and arm64 executables and
packages the installer, systemd template, guides and per-archive SHA-256 manifests.
The amd64 archive is extracted and its built-in selftest and staged installer are
exercised locally. The arm64 executable is built but not run here. CI/draft-release
workflow YAML is structurally checked locally; execution on GitHub is pending upload.


## v0.4.1-alpha compatibility change

The original 28 test functions remain. Five additional tests cover encrypted
negotiation: exact TCP and reverse payloads with half-close, zero and maximum UDP
datagrams, probes on all three listeners, invalid/cross-protocol/truncated
prefaces, wrong trust roots and server hostname, TLS timeout socket cleanup, and
mismatched ALPN/preface profiles. These are local checks, not WAN validation.


## v0.4.2-alpha identity verification

The new client option is tested with an observed empty ClientHello server name,
real direct/reverse/UDP transfers and authenticated probes, rejection of wrong
CA and wrong hostname, and verifier checks for expired, not-yet-valid,
client-only and missing server certificates. TLS 1.3 mutual authentication is
retained. Local tests do not establish WAN reachability or censorship cause.


## v0.4.3-alpha lifecycle checks

Five additional top-level tests cover slot recovery after a failed TLS
handshake and capacity rejection, a response delayed until after request EOF
with observable half-close gauges, a real relay idle expiry with TLS close
notification and separate counter, real TCP reset versus process shutdown,
and bounded event history without raw-error leakage. Existing tests remain
required. Direct-only diagnostic changes and local test success do not prove
the cause of historical WAN rejections or establish higher capacity.


## v0.4.4-alpha operation attribution

Three additional top-level tests inject read, write and CloseWrite failures on
both relay sides; check primary-error preservation, immutable counter snapshots,
bounded symbolic codes, redaction, exact clean-EOF handling and errors.Is/As.
The existing real TCP/TLS half-close, idle, reset, cancellation and payload tests
remain required. Tests cannot identify historical WAN io_error causes. The new
metadata reports the local failing operation, not an independently proven cause.


## v0.4.5-alpha half-close regression

A fault-based delayed binary response test fails on the previous bridge behavior:
CloseWrite ENOTCONN closes the still-needed response direction. After the change,
exact payload and byte counts must be preserved. A second test checks subsequent
reset, idle timeout, process cancellation and unchanged uninstrumented legacy
bridge behavior. Read/write ENOTCONN and other CloseWrite failures remain covered
by the operation-attribution test. This is a local regression, not proof of data
loss in historical WAN sessions or a benchmark.

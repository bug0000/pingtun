# Development validation — 2026-10-17

Linux amd64, official Go 1.27.2 toolchain. New 0.3.0 pairs default to protocol v2;
these are laboratory observations, not production or censorship-resistance
certification. See [LAB.md](LAB.md) for reproduction and limits.

## Automated checks

- `go test -race ./...`: legacy/adaptive carrier exchange, real WireGuard handshake
  over in-memory sockets, bidirectional exact inner-IP comparison, idle/wakeup,
  repeated server bind restarts, queue/controller bounds, replay, cancellation,
  parser/authentication and config validation.
- Raw diagnostics reject kernel reflections, modified or replayed frames, and
  handle cancellation/loss with bounded state.
- Frame tests cover all-byte mutation and separation of PTUN v1, PTUN v2 and PTPB
  domains. Fuzz targets cover all three decoders.
- Linux namespace script exercises actual raw ICMP, TUN, NAT and scoped nftables,
  duplicate-reply filtering, netem impairments and encrypted file integrity.
- `go vet ./...`, formatting/diff checks, Linux amd64 build and CLI config check
  passed. Linux arm64 cross-compilation passed; that binary was not executed.
- Ten seconds per decoder fuzz target completed without failure: 514,626 v1,
  485,331 diagnostic and 458,482 adaptive executions in the recorded run.

CI runs race/vet/fuzz/build checks and separate legacy/adaptive namespace jobs.
Check remote CI for the published commit. Parser fuzzing is not a security audit.

## Recorded local measurements

Single runs, shared local machine, one Linux NAT, 1280-byte outer wire MTU,
1000-byte inner MTU, 40 ms base RTT and two logical lanes. Application rates
include TCP, WireGuard and carrier overhead. Random impairments and scheduler
load vary, so these are not statistical comparisons.

| Case | Result |
|---|---|
| Raw ICMP, 1000 requests/s, no injected loss, stable and rotating IDs | Both returned every modified authenticated response; about 9.5 Mbit/s generated payload, 10.24 Mbit/s transmitted wire rate |
| Raw ICMP, 500 requests/s, 2% loss per leg + jitter/reordering | About 4–5% unconfirmed requests; loss can occur in either direction |
| V1, 256 KiB, impaired path | Download 78,171 B/s; upload 40,327 B/s |
| V2, 256 KiB, impaired path | Download 82,474 B/s; upload 80,999 B/s |
| V2, 4 MiB, zero injected loss, jitter/reordering retained | Download 811,185 B/s (6.49 Mbit/s); upload 753,087 B/s (6.02 Mbit/s) |
| V2, quiet 1.2 s sample | Client sent 324 IPv4 wire bytes; short interval excludes later WireGuard keepalives |
| V2, 1.5 s complete blackout | File resumed with matching content |
| V2, server restart | Fresh encrypted transfer succeeded without restarting the client; one epoch change recorded |
| V2, rotating IDs, impaired path, 3 min repeated-transfer run | 65 successful checksum-verified downloads; observed client RSS 19,604–22,796 KiB |
| V2, dedicated Ubuntu 22.04 VM, 10 min impaired-path run | 222 successful checksum-verified downloads; client RSS 14,384–19,020 KiB; blackout and server restart checks passed; host routes/rules unchanged |

The v1/v2 small-file rows are separate runs, not a controlled performance claim.
The larger-file row demonstrates headroom in this lab; it does not establish a
remote ICMP ceiling. Final expiry counters include deliberate outage tests.

External diagnostic observations varied over time. Interleaved identifier tests
did not isolate a stable mode-specific cause, or establish that rotating IDs,
NAT or a particular filtering system caused the issue. Development measurements
now use the isolated lab to separate implementation behavior from that path.

## Android checks

- Go race tests and vet pass, including the shared engine with real WireGuard,
  server restart recovery, supplied TUN lifetime and key-free statistics.
- ICMP datagram adapter tests cover kernel identifier rewriting, bounded
  sequence tickets, reflection/foreign-source rejection and close cancellation.
- Full Linux NAT lab passes with `CAP_NET_RAW` removed from the client and raw
  ICMP socket creation explicitly denied: encrypted download/upload hashes,
  quiet traffic, total blackout recovery and server restart all pass. The
  recorded quiet sample was 324 IPv4 wire bytes over 1.2 seconds.
- JNI libraries build for Android arm64-v8a/x86_64. ELF LOAD segments align to
  16 KiB. Debug/release APKs and instrumentation APK build; Android lint and
  release vital checks pass (dependency-version/localization warnings remain).
- Stock Android 15/x86_64 emulator: application installs and launches; all
  three instrumentation tests pass under the app UID (unprivileged ICMP socket
  creation, private metadata, Keystore encryption and tamper detection).
  The Android workflow records its launch screenshot and test output.

Initial phone test on 2026-10-17: a physical Android device without root connected over LTE and opened websites. An independent
server instance with a separate peer identity recorded authenticated carrier
datagrams and bidirectional forwarded IPv4 traffic with NAT. The existing
gateway binaries and services were not upgraded or restarted for this test.
The phone's exact OS build and operator were not recorded. This validates one
basic browsing case; Wi-Fi/mobile handoff, Doze, IPv6 bypass checks, lockdown,
long sessions and throughput remain unverified on the phone.

## Release 0.3.0 checks

- Linux CLI now uses the same engine as Android, including initial handshake
  and recovery after server restart. Race tests and vet pass.
- Generated v2 defaults, explicit legacy generation and the exact 64 KiB config
  size boundary have regression coverage.
- The unprivileged ICMP NAT lab passes with the release CLI and the new TUN
  address helper: encrypted upload/download checksums, loss/reordering, blackout
  and server restart without restarting the client. One 1.2 s quiet sample
  recorded 216 IPv4 wire bytes; this excludes later keepalives.
- Android 0.3.0, versionCode 2, builds for both ABIs. The signed non-debuggable
  APK passes signature, package/version, certificate continuity and 16 KiB
  alignment checks. The private signing key is not stored in the repository.
- govulncheck v1.9.0 reports no reachable vulnerabilities and no vulnerabilities
  in imported packages. It reports GO-2026-5932 in the dependency module's
  OpenPGP package, which this project does not import or link.
- Publication requires both Linux CI and Android checks to pass on the current
  main commit. Linux archives are built from that commit; ARM64 startup and
  generated-config validation are also checked under QEMU before publication.

## Remaining validation

Longer soaks, fairness under competing traffic, diverse real NAT/firewalls,
concurrent bidirectional load, MTU/fragmentation tests, state-machine fuzzing,
independent review and bounded live-path validation. Physical multipath, FEC,
multiple peers and production failover are not implemented. The Android arm64 engine now has one reported hardware run. The Linux
arm64 CLI still needs testing on real Linux ARM64 hardware; QEMU smoke checks
do not validate its TUN/raw-socket behavior on a physical machine.

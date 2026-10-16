# Development validation — 2026-10-16

Linux amd64, official Go 1.27.2 toolchain. Protocol v2 is an experimental opt-in;
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

## Still required

Longer soaks, fairness under competing traffic, diverse real NAT/firewalls,
concurrent bidirectional load, MTU/fragmentation tests, state-machine fuzzing,
independent review and bounded live-path validation. Physical multipath, FEC,
multiple peers and production failover are not implemented. The arm64 build
must be executed on real hardware before claiming runtime support.

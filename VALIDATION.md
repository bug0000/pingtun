# Local validation — 2026-10-16

Tested on Linux amd64 with the official Go 1.27.2 toolchain (distribution SHA-256
verified). This is a developer-preview snapshot, not a production certification.

Passed:

- `go test -race ./...`: config generation/permissions, authenticated frame
  corruption and freshness, sliding replay window, duplicate request rejection,
  blocked receive shutdown, and real WireGuard end-to-end integration.
- Integration: 12 distinct IPv4 packets in each direction, two logical lanes,
  exact packet-content comparison, and absence of the known plaintext marker
  in captured carrier frames. The echo sockets and TUN are in memory.
- `go vet ./...`.
- `go test ./internal/wire -run '^$' -fuzz FuzzDecode -fuzztime 10s -parallel 2`:
  499,360 fuzz executions without a failure.
- Linux amd64 build and CLI `version`, `init`, and `check` smoke tests.
- Linux arm64 cross-compilation; the arm64 binary has not been executed.

Not tested: real raw-ICMP socket exchange, NAT/firewall behavior, nftables rule
application, systemd deployment, sustained throughput, loss/jitter/reordering,
multi-client operation, or production failover. No deployed server was used to
validate this new implementation. Those tests belong to the isolated lab stage.

The GitHub Actions workflow is supplied, but its remote execution must be
confirmed after publication. Parser fuzzing does not replace a security audit.

# pingtun

[Русский](README.ru.md) · [Install](INSTALL.md) · [Release 0.3.0](https://github.com/bug0000/pingtun/releases/tag/v0.3.0)

**pingtun 0.3.0** is an encrypted IPv4 VPN over ICMP Echo Request/Reply.
The Linux binary supports both server and CLI client; the Android application
uses the system VPN API and ICMP datagram sockets without root or Google Play
Services. WireGuard-go supplies peer authentication, encryption and replay
protection. The carrier is written in Go; no Hans code is included.

## Downloads

The [GitHub release](https://github.com/bug0000/pingtun/releases/tag/v0.3.0)
contains Linux amd64/arm64 archives, a signed Android 10+ APK, SHA256SUMS and
license notices. Android uses the same signing identity as the previous app
build (versionCode now 2), so it can update it in place. No signing private key,
VPN profile or live configuration is included. The Android UI is currently Russian.

## Features and boundaries

- Adaptive v2: short idle controls, a shared packet pacer/window, bounded queues,
  logical lanes, server restart recovery and key-free statistics.
- One encrypted peer per server instance; independent keys for every client.
- An optional [web admin console](admin/README.ru.md) provisions and manages
  separate instances for Android and Linux clients.
- `init` creates v2 pairs with stable IDs, MTU 1280 / outer MTU 1440, two lanes,
  a 250 packets/s ceiling and a 32-request maximum window. `init --legacy`
  creates v1 pairs. Existing configs/profiles keep their protocol and identity.
- `mobile-init` creates a dedicated Android profile. Android stores it with
  Keystore AES-GCM and retains its TUN while recovering the transport.
- `probe`/`probe-server` measure authenticated ICMP separately from VPN traffic.
- The Linux daemon creates only its own TUN. Manual deployments configure
  routing, forwarding and NAT explicitly. See [INSTALL.md](INSTALL.md).

This release carries **IPv4 only**. Android captures and blocks IPv6. Multiple
logical lanes share one path and are not physical aggregation. Physical
multipath, FEC, Windows, multiple peers per instance and automatic network
failover are not included. ICMP can be blocked or rate-limited. No external
security audit has been completed; see [SECURITY.md](SECURITY.md).

## Quick start

```sh
pingtun version
pingtun init --server 203.0.113.10 --dir configs
pingtun check --config configs/server.json
# For a separate phone identity:
pingtun mobile-init --server 203.0.113.10 --dir configs-phone --name Phone --address 10.203.0.2/30
```

Replace the documentation address and choose a non-overlapping private subnet.
Generated directories are 0700 and secret files are 0600; existing directories
are refused. Install configs as root-owned files for the capability-confined
service. Never publish them or reuse a gateway's identity on a phone. Full
server, Linux client and Android instructions are in [INSTALL.md](INSTALL.md)
and [android/README.md](android/README.md).

## Build and validation

Linux, Go 1.27.2:

```sh
go test -race ./...
go vet ./...
go build -trimpath -buildvcs=false -o bin/pingtun ./cmd/pingtun
```

CI includes decoder fuzzing, dependency scanning, real WireGuard and Linux
namespace tests with NAT, loss/reordering, encrypted file checks, blackout and
server restart recovery. A datagram client is tested with CAP_NET_RAW removed.
Android CI checks launch, app-UID ICMP and authenticated profile storage in an
Android 15 emulator. A user confirmed initial LTE browsing on a Pixel 9 Pro
with GrapheneOS and no root. This is one device/network case; sleep, handoff,
IPv6 bypass, lockdown and longer sessions still need device validation.

See [VALIDATION.md](VALIDATION.md), [LAB.md](LAB.md), [PROTOCOL.md](PROTOCOL.md),
[CHANGELOG.md](CHANGELOG.md), [ROADMAP.md](ROADMAP.md) and [RELEASE_NOTES.md](RELEASE_NOTES.md).

## License

MIT. Bundles include third-party notices; dependencies retain their licenses.

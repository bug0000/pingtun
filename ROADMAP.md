# Roadmap

## First regular release: 0.3.0

- Linux amd64/arm64 server and CLI client, with a shared encrypted engine.
- Signed Android 10+ client without root or Google Play Services; private
  profile import and Keystore storage, bounded network recovery and optional
  screen-off wake lock. One Pixel 9 Pro/GrapheneOS LTE browsing case confirmed.
- New pairs default to adaptive v2; existing profiles remain compatible and
  `init --legacy` explicitly generates v1.
- Russian/English release and installation guides, checksums, dependency notices
  and gated publication after Linux/Android CI.

## Earlier development milestones

- V0.1: Linux TUN, WireGuard-go over authenticated ICMP request/reply credits,
  secure config generation, explicit MTU checks and bounded queues.
- Multiple logical lanes within one encrypted peer session; explicit routing
  and deployment documentation.
- Independent raw ICMP diagnostics: modified authenticated replies, pacing,
  identifier modes, JSON accounting and bounded duration.
- V0.2 experimental opt-in: short idle controls, shared pacer/adaptive window,
  reserved data capacity, holding-time feedback, restart recovery and key-free
  counters. Legacy v1 was the default before 0.3.0.
- In-memory integration, race/parser fuzz checks, Linux NAT lab with impairments,
  encrypted file checks, blackout and server restart recovery.

## Next: stable, efficient use of a measured ICMP path

1. Expand repeatable benchmarks: longer idle/active transitions, concurrent
   bidirectional load, CPU/wire overhead, competing flows and controller fairness.
   Compare identical path traces, not unrelated sequential speed samples.
2. Improve behavior under burst loss and rate-limit changes. Separate capacity,
   loss, RTT and scheduler limits; keep hard caps and bounded memory.
3. Expand NAT/firewall, client restart, MTU/PMTU and fragmentation tests. Exercise
   arm64, multiple kernel/nftables versions and long-running WireGuard sessions.
   On phones: Wi-Fi/mobile handoff, Doze, process death, IPv6 bypass checks and
   system VPN lockdown under prolonged outages.
4. State-machine fuzzing, privilege separation, source cookies/admission review,
   reproducible builds, dependency scanning and independent security review.
5. After bounded live-path validation: opt-in fallback with management/endpoint
   exclusions, rollback timer, hysteresis and recovery to the preferred VPN.

## Later experiments

- Separate physical endpoints/paths, measured RTT/loss and an adaptive scheduler.
- Optional duplication for control traffic and bounded FEC for loss, measured
  against added wire cost and existing TCP retransmission.
- MTU probing/negotiation, IPv6 and multiple peers with separate fair queues.

FEC and additional logical lanes cannot manufacture capacity under a shared
ICMP limit. Physical aggregation is a later experiment, not a current feature.

# Roadmap

## v0.1 developer preview — implemented

- Linux TUN + authenticated ICMP request/reply carrier.
- WireGuard-go integration, secure config-pair generator, bounds and MTU checks.
- Multiple logical lanes within a single encrypted peer session.
- In-memory end-to-end encryption/transport tests, race checks and parser fuzzing.
- Explicit routing and isolated deployment documentation.

## Required before a real fallback deployment

1. Network-namespace lab: client NAT router, server, one-reply-per-request filter,
   kernel duplicate echoes, loss, jitter, reordering, fragmentation/PMTU limits.
2. Tests across client/server restarts and long idle periods; request expiry and
   retransmission pressure; assert bounded memory throughout.
3. File-integrity and throughput measurements in both directions. Compare one
   lane with 2/4 lanes, counting idle/total bandwidth and CPU, not just payload rate.
4. State-machine fuzzing, parser review, per-source/admission rate limits and
   source cookies. Review restart replay semantics and privilege separation.
5. A control/status interface with meaningful live health metrics; reproducible
   builds, dependency scanning and independent security review.
6. Only then: an opt-in last-resort failover integration with a rollback timer,
   management/endpoint exclusions, hysteresis and recovery to the preferred VPN.

## Later experiments

- Separate physical endpoints/paths with measured RTT/loss and an adaptive
  scheduler. Keep logical session identity independent of public source address.
- Optional duplication for control packets and bounded FEC for lossy paths.
- MTU probing/negotiation and IPv6 inner-packet support.
- Multiple independent authenticated peers with separate queues and fair limits.
- A paced congestion controller and idle polling backoff with a documented
  tradeoff between wakeup latency, capacity and background bandwidth.

These features are not claimed by the current build. In particular, FEC and
additional logical lanes cannot manufacture capacity under a shared ICMP limit.

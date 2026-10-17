# Security model and review status

Version 0.3.0 is the first regular release. No independent security audit has
been completed. Laboratory coverage and one reported Android browsing test do
not establish security, compatibility or availability on every network.

## Trust boundaries

- WireGuard-go provides end-to-end peer authentication, encryption, forward-secret
  sessions and inner-packet replay protection. We use its implementation rather
  than a new encryption scheme. This does not constitute an audit of our adapter.
- Independent randomly generated carrier keys authenticate polling/control frames
  with HMAC-SHA-256 truncated to 128 bits. Carrier metadata is visible in plaintext.
- A party that knows only the carrier key cannot decrypt inner WireGuard traffic,
  but can consume credits, interfere with routing of replies and cause denial of
  service. Do not share transport keys between unrelated pairs.
- WireGuard public keys and `allowed_ips` define the configured peer and permitted
  inner source addresses. Do not reuse private keys across independent clients.
- The process needs access to TUN and raw ICMP sockets. The sample service bounds
  capabilities but is not a complete sandbox. Review it on the target distribution.

## Protections in this version

Authenticated lengths and padding; freshness checks; bounded replay windows and
session caches; bounded packet/request queues; exact outstanding-ticket matching;
one equal-size response per authenticated request; secure config-file permissions;
no keys in normal output; no shell execution for interface or route configuration.
Existing interface names are rejected. Default routes, forwarding and firewall
are never changed by the daemon.

## Known gaps

- Linux NAT/firewall behavior and echo suppression have isolated lab coverage.
  Initial Android v2 browsing over LTE was confirmed on one Pixel 9 Pro with
  GrapheneOS; broader device/network behavior remains unvalidated. The supplied
  nft files are **not applied by the daemon**.
- A valid carrier MAC is not a stateless source-address cookie. A party holding
  the carrier key can spoof addresses where its network allows spoofing.
- Server cache replay state is not persistent across restarts; see PROTOCOL.md.
- V2 and the diagnostic responder have a global authenticated admission limit;
  v1 has no such limiter. There is no independent per-source/cookie-based admission
  control. Bounded memory is not protection from CPU/packet-rate exhaustion.
- V2's packet pacer and AIMD-like window are experimental, not a proven congestion
  controller. A carrier-key holder can also spoof restart epochs and disrupt the
  encrypted peer. Epochs are liveness hints, not replacements for WireGuard identity.
- V2 reveals idle/active transitions through short control frames versus full
  data frames; the reduced background traffic is not traffic camouflage.
- Clock freshness depends on synchronized clocks. There is no protocol negotiation
  for changing MTU, keys, lanes or version while running.
- Fuzz tests cover the carrier decoder; they are not a full protocol-state fuzzer.
- Dependencies, raw-socket behavior and systemd confinement need independent review.
- No ICMP traffic camouflage, censorship-resistance guarantee or availability
  guarantee is made. ICMP can be blocked or rate-limited altogether.

## Reporting

Avoid posting private keys, real client addresses or sensitive packet captures in
public issues. A dedicated private vulnerability-reporting channel must be set up
by the repository owner before accepting production users.

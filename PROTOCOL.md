# Carrier protocols (experimental)

## Layers

```text
inner IPv4 packet
  -> WireGuard userspace device: handshake / encryption / anti-replay
    -> pingtun conn.Bind: bounded datagram queue
      -> authenticated, padded carrier frame
        -> IPv4 ICMP echo request (client) / echo reply (server)
```

This is a new carrier, not a reimplementation of WireGuard cryptography. It is
incompatible with ordinary WireGuard UDP endpoints and with Hans.

## Legacy v1 frame

All integers are big-endian. ICMP payload size is `wire_mtu - 28`. The outer IP
header is assumed to be the normal 20-byte IPv4 header and ICMP adds 8 bytes.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | `PTUN` magic |
| 4 | 1 | version: 1 |
| 5 | 1 | kind: request 1, response 2 |
| 6 | 2 | logical lane number |
| 8 | 16 | cryptographically random client session ID |
| 24 | 8 | client request counter |
| 32 | 8 | Unix timestamp in seconds |
| 40 | 2 | WireGuard datagram length (zero for poll/empty ACK) |
| 42 | 16 | first 16 bytes of HMAC-SHA-256 |
| 58 | variable | WireGuard datagram, then zero padding |

HMAC input is bytes 0–41 followed by bytes 58–end, including all padding. A
separate random 32-byte carrier key is required. Kind is authenticated, so a
kernel's reflected request is not a valid server response. Received frame sizes
must match configuration exactly. Timestamps must be within 30 seconds; clocks
must be synchronized.

The carrier does not expose or manipulate WireGuard's session keys.

## Request/reply credits and NAT

Clients maintain `lanes × window` requests. Each request has a unique counter
within its random session. Echo ID and sequence derive from different bits of
that counter; live requests do not share an ID at the permitted window size.
The client records the request counter, session, lane, ICMP ID/sequence and
deadline. A response must match every field and consumes its ticket once.

A server validates the MAC and freshness before admitting a frame into session
state. It maintains a 1024-counter sliding replay window for each session, at
most 8 recent sessions and 256 waiting requests. A response returns one queued
WireGuard datagram for that source IP, or an empty ACK after `hold_ms`.
The response echoes the request's ticket and is exactly the request's size.
Expired requests are not reused; a new request replaces a lost one. Carrier
datagrams themselves are best effort, like the UDP transport they replace.

Session entries expire after two minutes of inactivity. This exceeds timestamp
freshness, so an expired entry cannot normally be resurrected by replaying its
old frames. Restarting the server clears the cache; the freshness interval is
therefore not durable replay protection across restart. WireGuard independently
authenticates and protects inner packets against replay. This limitation still
requires adversarial testing before exposure to an untrusted Internet.

The current daemon supports one configured WireGuard peer. Multiple independent
clients sharing keys are unsupported. Random session IDs prevent accidental
IP-only identity conflation, but do not make the single-peer configuration a
multi-user VPN service.

## Memory and limits

- 1–8 lanes; 1–16 requests per lane.
- Configured outer wire MTU 512–1500; fixed padding.
- Incoming events, encrypted outbound datagrams and delivered datagrams: 256
  entries per queue, each bounded by the frame budget.
- Queued outgoing datagrams expire after 5 seconds.
- Server waiting requests: 256; excess authenticated requests get an empty ACK.
- Server replay sessions: 8, each with a 1024-bit sliding window.
- A queue overflow drops a packet; it never allocates an unbounded backlog.

The inner TUN MTU must fit the 58-byte carrier header, IPv4+ICMP overhead and
WireGuard's 32-byte transport overhead plus 16-byte padding alignment. IPv6 inner
routing and IP fragmentation/reassembly in the carrier are not supported.

## Logical aggregation

All lanes feed one WireGuard device, its encrypted packet queue and its receive
path. Replies consume tickets in arrival order; payload can be returned through
any waiting lane for the authenticated source. The client replenishes every lane
to its configured window. Packets may arrive out of order; the carrier introduces
no TCP-like ordered stream or head-of-line blocking.

This is concurrent request credit, not adaptive physical multipath. There is no
bandwidth estimator, RTT scheduler, congestion controller or independent path
failure detector in v1. Multiple lanes on one source/destination path share
provider rate limits. More lanes can increase overhead or loss instead of speed.

## Adaptive v2 frame

V2 requires an `adaptive` object on both endpoints. V1 remains the default; the
modes reject each other's frames without negotiation or silent downgrade.
V2 retains the same cryptographic layers and single-peer restrictions.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | `PTUN` magic |
| 4 | 1 | version: 2 |
| 5 | 1 | kind: request 1, response 2 |
| 6 | 2 | logical lane |
| 8 | 16 | random client session ID |
| 24 | 8 | request counter |
| 32 | 8 | Unix timestamp, seconds |
| 40 | 2 | WireGuard datagram length |
| 42 | 2 | queued response datagrams for this source (hint) |
| 44 | 8 | nonzero server generation epoch in responses |
| 52 | 4 | server holding time, microseconds |
| 56 | 1 | flags: bit 0 = short control |
| 57 | 7 | reserved, must be zero |
| 64 | 16 | truncated HMAC-SHA-256 |
| 80 | variable | WireGuard datagram, then zero padding |

The MAC covers bytes 0–63 followed by bytes 80–end, including padding. Freshness
is 30 seconds. Requests must have zero backlog, epoch and holding time; responses
must have a nonzero epoch. Unknown flags and nonzero reserved bytes are rejected.
A short control has no payload and exactly 80 ICMP payload bytes (108 IPv4 wire
bytes). All other frames use the configured full wire size.

Each admitted request grants at most one **equal-size** response, matched to its
ICMP tuple, counter, session, lane and control flag. Short controls are answered
immediately and advertise only backlog/epoch; data requires a full-size credit.
The server holds empty full-size requests for up to 25 ms, or data-carrying
requests for up to 5 ms, subject to scheduler timing. Ready data can be returned
earlier. Responses authenticate actual holding time.

### Pacing, idle and recovery

All lanes share a token-bucket pacer with a four-packet burst and one adaptive
window capped at 128. It starts at `max(4, lanes × window)`, capped by
`max_window`. Useful acknowledgements grow it additively; expiry halves it to a
floor of two, at most once per RTT (minimum 100 ms). Pacing is capped by both
`max_pps` and approximately `1.1 × window / max(RTT, 5 ms)`. RTT is an EWMA after
subtracting authenticated holding time. Request timeout adapts with RTT and
backs off on loss, capped by configured carrier timeout. This initial controller
is not yet a validated TCP-fair congestion-control algorithm.

Outbound datagrams take priority over empty polls. Empty polls reserve a quarter
of the current window (at least one slot) for data. After activity grace of
`max(150 ms, 2 × RTT)`, the client returns to one short control per `idle_ms`.
Server-originated traffic may wait for that control and a full-size credit.
WireGuard keepalives add traffic. No carrier retransmission or ordered byte
stream is introduced.

The server has one authenticated admission limiter (`max_pps`, burst 32), eight
replay sessions, 256 waiting credits and bounded datagram queues. Limiting
follows MAC validation; it does not protect against arbitrary raw traffic CPU
exhaustion. V1's cross-restart replay-cache limitation also applies.

The server chooses a fresh random nonzero 64-bit epoch per bind generation.
A changed epoch in a valid current ticket clears client stale ciphertext and
credits and signals the daemon to recreate its configured WireGuard peer,
preserving the TUN and routes. A bounded FIFO remembers eight retired epochs.
This is single-peer restart recovery, not durable epoch history, zero-loss
migration or multi-server failover. A carrier-key holder can forge metadata and
force disruptive resets.

`stable` ID mode uses a fixed random-base identifier per lane with changing
16-bit sequences. `rotate` maps low counter bits to ID and higher bits to sequence,
preserving v1's pattern. Neither mode guarantees traversal of a specific firewall.

### Observability

SIGUSR1 or `run --stats-interval` emits key-free JSON. V2 includes wire bytes,
data/control frames, window/peak outstanding, estimated RTT, admission limiting,
expiry and peer restarts. Snapshots read separate atomic counters and are
approximate, not transactional. V1 reports basic counts; extra v2 metrics may
remain zero. Wire bytes exclude link headers, invalid traffic and kernel echoes.

## Diagnostic domain

`probe` / `probe-server` use the v1 58-byte layout with **`PTPB`** magic included
in the MAC. Tunnel parsers reject this domain. Payload is a counter-derived test
pattern; the responder XORs every byte with `0xa5` and changes the authenticated
kind. Kernel reflections cannot be successful responses. Probes contain no user
IP or WireGuard packets. Replay state and admission rate are bounded; each fresh
request grants one equal-size response.

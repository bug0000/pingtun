# Carrier protocol v1 (experimental)

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

## Frame

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

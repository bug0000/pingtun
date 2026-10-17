# pingtun

An experimental encrypted IPv4 tunnel carried by ICMP echo requests and replies.
Written from scratch in Go. No Hans code is included.

**Status: developer preview, not a production VPN.** The encrypted engine and
carrier are tested in memory and in an isolated Linux NAT lab with real TUN/raw
sockets, loss and reordering. Protocol v2 is an explicit experimental opt-in.
Measured lab results are not guarantees for a provider or filtering device.

An [Android client preview](android/README.md) is available for Android 10+
(arm64/x86_64). It uses the system VPN API and ICMP datagram sockets without
requesting root. Device compatibility and network handoff still need testing.

## What works

- WireGuard's userspace implementation handles the authenticated key exchange,
  encryption, replay protection and inner IPv4 peer authorization.
- A custom ICMP `conn.Bind` replaces its UDP transport. WireGuard datagrams are
  carried directly inside ICMP, without a separate outer UDP/IP layer.
- A separate 256-bit carrier key authenticates requests, polls and replies.
- Bounded queues, a bounded replay window, request expiry and padded frames.
- 1–8 logical lanes and 1–16 outstanding requests per lane share **one encrypted
  peer session**. A session is not identified merely by a client's public IP.
- Secure config-pair generation, explicit MTU validation, shutdown counters and
  a systemd example.
- Independent authenticated ICMP diagnostics without TUN/WireGuard, with JSON
  packet accounting and stable/rotating identifier modes.
- Experimental v2: short idle controls, reserved data capacity, a shared packet
  pacer and adaptive window, bounded restart detection and key-free snapshots.

Logical lanes provide concurrent request/reply slots and packet distribution.
They are not independent physical paths, do not evade a shared ICMP rate limit,
and do not guarantee a speedup. Physical multipath, FEC, IPv6 and automatic
routing/failover are **not implemented**. V2's initial window controller still
needs fairness, interoperability and longer stability testing.

## Build and test

Linux and Go 1.26 or newer:

```sh
go test -race ./...
go vet ./...
go build -trimpath -o bin/pingtun ./cmd/pingtun
```

The tests include a real WireGuard handshake and bidirectional inner-IP traffic
through the carrier over in-memory echo sockets. They do not need root, TUN or
Internet access after dependencies have been downloaded.

For real TUN, NAT/firewall and recovery checks, see [LAB.md](LAB.md). The lab
always creates new user/network/mount namespaces and never edits host routes.

## Generate a pair

```sh
bin/pingtun init --server 203.0.113.10 --dir configs
bin/pingtun check --config configs/server.json
bin/pingtun check --config configs/client.json
```

Replace the documentation-only server address. `init` refuses an existing
directory, creates it with mode 0700 and writes both configs with mode 0600.
It prints paths, never keys. Keep `server.json` on the server and `client.json`
on the client. Each contains one private WireGuard key and the shared carrier
key. Never commit these files. `check` needs no privileges.

When installing a config for the supplied root service with bounded capabilities,
set its owner explicitly, e.g.
`sudo install -o root -g root -m 600 configs/server.json /etc/pingtun/server.json`. Mode 0600 with a different owner
can prevent the confined service from reading it even when its UID is root.

## Isolated first run

Run each daemon with root privileges, or equivalent `CAP_NET_ADMIN` and
`CAP_NET_RAW` capabilities plus access to `/dev/net/tun`:

```sh
sudo bin/pingtun run --config /etc/pingtun/server.json
# On the other machine:
sudo bin/pingtun run --config /etc/pingtun/client.json
```

In separate terminals, assign addresses **after** the daemons have created their
interfaces:

```sh
# Server:
sudo ip address add 10.203.0.1/30 dev pingtun0
sudo ip link set pingtun0 up
# Client:
sudo ip address add 10.203.0.2/30 dev pingtun0
sudo ip link set pingtun0 up
ping -I 10.203.0.2 10.203.0.1
```

Choose a private subnet that does not overlap your network. The daemon creates
only its own TUN device; it never edits default routes, forwarding, NAT, firewall
or existing VPNs. The generated `allowed_ips` authorizes traffic cryptographically;
it does **not** install routes. Internet forwarding requires a separately reviewed
server forwarding/NAT configuration and an explicit client policy route. Preserve
a direct route to the public ICMP endpoint before testing routed traffic. Existing
policy routing can otherwise capture even the private test subnet.

### Kernel echo replies

The kernel may also answer ICMP requests. Those reflected request frames are
rejected by pingtun, but can interfere with NAT that permits only one reply per
request. On the server, [deploy/kernel-echo.nft](deploy/kernel-echo.nft) suppresses
only reflected pingtun **request** frames. Ordinary ping replies and legitimate
pingtun responses are preserved. Review the rule before applying it:

```sh
sudo nft -f deploy/kernel-echo.nft
# Remove only pingtun's table:
sudo nft delete table ip pingtun_echo
```

Do not disable all kernel echo replies globally.

### Parallel lanes

This section describes the default legacy v1 transport.

Set matching `lanes` values in both configs. Start with `lanes: 1, window: 2`.
Compare against `lanes: 2, window: 2` in an isolated lab. Larger windows consume
more idle bandwidth: with full-size padded requests and replies, the approximate
idle wire rate is `2 × lanes × window × wire_mtu / hold_seconds` bytes/second,
excluding Ethernet headers. With defaults this is about **82 kbit/s** across both
directions. Authentication/keepalive/data can add traffic.

Each reply consumes exactly one authenticated request. Outstanding requests use
distinct echo identifiers; the receiver never reuses an old request for a second
reply. Loss is not retransmitted by the carrier: higher-layer protocols recover,
and WireGuard handles its handshake retries.

### Experimental adaptive transport (v2)

Add this object to **both** generated configs; keep matching MTU and lane values:

```json
"adaptive": {"max_pps": 1000, "max_window": 128, "idle_ms": 500, "id_mode": "rotate"}
```

V2 is incompatible with v1. Removing the object selects v1. Install the server's
separate [v2 echo rule](deploy/adaptive-kernel-echo.nft), not just the v1 rule.
The daemon itself never installs firewall rules.

Idle controls are 108 IPv4 bytes and each receives one equally sized reply.
They only advertise queued data; larger requests then grant equally sized data
replies. This avoids relying on a small request authorizing a large response.
At a 500 ms idle interval, the control exchange is about 3.46 kbit/s across both
directions before delivery delays; WireGuard keepalives and wakeup bursts add
traffic. Active packets share one paced window across all logical lanes.

The server reports its hold time separately from RTT. Timeouts reduce the window;
useful replies increase it. Empty polls leave space for new uploads. There is no
outer reliable byte stream and no retransmission of arbitrary IP datagrams.

An authenticated server epoch change resets the client's configured WireGuard
peer to establish a new encrypted session, preserving its TUN and routes. This
is not a guarantee of zero packet loss or uninterrupted application sessions.

`id_mode: stable` reuses one identifier per logical lane with changing sequences.
`rotate` preserves the legacy identifier pattern. Measure both on the target
path; a time-varying link can make sequential A/B tests misleading.

Use `run --stats-interval 5s` or send SIGUSR1 to obtain JSON counters without keys.
See [PROTOCOL.md](PROTOCOL.md), [LAB.md](LAB.md) and [VALIDATION.md](VALIDATION.md).

See [PROTOCOL.md](PROTOCOL.md), [SECURITY.md](SECURITY.md),
[ROADMAP.md](ROADMAP.md) and the [Russian overview](README.ru.md).

## License

MIT. WireGuard-go and other dependencies retain their respective licenses.
This project has not received an independent security audit.

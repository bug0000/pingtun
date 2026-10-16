# pingtun

An experimental encrypted IPv4 tunnel carried by ICMP echo requests and replies.
Written from scratch in Go. No Hans code is included.

**Status: developer preview, not a production VPN.** The encrypted engine and
carrier are tested together in memory; deployment over real NAT/firewalls still
needs a separate lab run. No throughput claims or production failover integration
are made.

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

Logical lanes provide concurrent request/reply slots and packet distribution.
They are not independent physical paths, do not evade a shared ICMP rate limit,
and do not guarantee a speedup. Adaptive multipath, congestion control, FEC,
IPv6 and automatic routing/failover are **not implemented**.

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

See [PROTOCOL.md](PROTOCOL.md), [SECURITY.md](SECURITY.md),
[ROADMAP.md](ROADMAP.md) and the [Russian overview](README.ru.md).

## License

MIT. WireGuard-go and other dependencies retain their respective licenses.
This project has not received an independent security audit.

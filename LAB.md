# Reproducible isolated Linux lab

Build first, then run from the repository root:

```sh
make build
./tests/netns.sh "$PWD/bin/pingtun" /tmp/pingtun-legacy-lab
PINGTUN_LAB_MODE=adaptive ./tests/netns.sh "$PWD/bin/pingtun" /tmp/pingtun-adaptive-lab
```

The output directory must not exist. It contains private generated configs with
mode 0600 as well as measurements. **Do not upload the entire directory.** Only
the JSON summaries and daemon logs are designed to be free of keys.

Requirements: Linux with user/network/mount namespaces, TUN, `unshare`, `ip`,
`nft`, `tc`, Python 3 and curl supporting `%{json}`. The script always starts a
new user, network and mount namespace, including when invoked as root. A host
that disables unprivileged user namespaces may require `sudo env ...`.
When using sudo, keep lab inputs/results in directories owned by root with
traversable ancestors. Root inside a user namespace cannot override permissions
on another user's private checkout. CI stages only its lab inputs under /tmp.

## Topology and checks

```text
client 10.200.1.2 -- NAT router -- server 192.0.2.2
      TUN 10.203.0.2/30 <----> TUN 10.203.0.1/30
```

All interfaces, forwarding, NAT, nftables, netem impairments and test HTTP
listeners live inside the new namespaces. No physical host interface, production
VPN, host firewall or default route is modified. Cleanup terminates lab processes
and removes its namespaces. Results remain on disk for inspection.

The router blocks unsolicited traffic and allows only one echo reply per
source/ICMP-ID/sequence tuple within five seconds. A test-only packet mark packs
ID and sequence for compatibility with nftables 1.0.2. There is no mark-based
routing in the lab. The server installs scoped rules suppressing reflected PTUN
v1/v2 and PTPB requests; ordinary ping replies are unaffected.

Default checks:

- Independent authenticated raw ICMP at 100/500/1000 requests/s, stable and
  rotating identifiers, 1280-byte IPv4 packets and 40 ms base RTT.
- Both identifier modes at 500 requests/s with 2% independent loss per leg,
  5 ms jitter and 10% reordering. A kernel echo is not a successful response.
- Real WireGuard handshake and TUN traffic through NAT on the impaired path.
  Download and upload a 256 KiB patterned fixture; verify content and SHA-256.
- Adaptive mode additionally checks low idle traffic, recovery from a 1.5 s
  total ICMP blackout and server restart without restarting the client.
  Outstanding requests and restart detection are asserted.

These checks model one Linux NAT/firewall; they do not certify every NAT,
filtering device or Internet path. Timing and random impairments vary by run.

## Parameters

| Environment variable | Default | Meaning |
|---|---|---|
| `PINGTUN_LAB_MODE` | `legacy` | `legacy` or opt-in `adaptive` |
| `PINGTUN_LAB_RAW` | `1` | Set `0` to skip the raw matrix |
| `PINGTUN_LAB_ID_MODE` | `stable` | Adaptive ID mode: `stable` or `rotate` |
| `PINGTUN_LAB_LOSS` | `2%` | netem loss per leg during tunnel tests |
| `PINGTUN_LAB_BYTES` | `262144` | Fixture size, 256 bytes to 16 MiB |
| `PINGTUN_LAB_SOAK_SECONDS` | `0` | Repeated checksum checks, 0–600 s |

The raw matrix has its own fixed cases. `PINGTUN_LAB_LOSS` applies to subsequent
tunnel checks. `0%` still retains jitter and reordering.

Example extended run:

```sh
PINGTUN_LAB_MODE=adaptive PINGTUN_LAB_RAW=0 PINGTUN_LAB_ID_MODE=rotate PINGTUN_LAB_SOAK_SECONDS=600 ./tests/netns.sh "$PWD/bin/pingtun" /tmp/pingtun-soak
```

Inspect `download.json` / `upload.json` for curl timing and application bytes/s,
`probe-summary.json` for raw measurements, `idle.json` for quiet client wire
bytes, `adaptive-summary.json` for final counters and `soak.tsv` for successful
transfers and client RSS in KiB. Expiry counts include intentional outages;
they are not clean-path loss measurements. CI runs both protocol modes and
prints key-free logs on failure without uploading private configs.

## Independent path diagnostics

Use a separately generated config pair. Diagnostic mode uses the configured
carrier key and listen/remote IPv4 addresses; it creates no TUN or routes.

```sh
# Server: bounded lifetime, one authenticated equal-size reply per request.
sudo nft -f deploy/probe-kernel-echo.nft
sudo bin/pingtun probe-server --config /etc/pingtun/server.json --duration 90s --max-pps 1000
# Client, during that interval:
sudo bin/pingtun probe --config /etc/pingtun/client.json --duration 10s --size 1280 --pps 100 --window 256 --timeout 1s --id-mode stable
# Repeat interleaved stable/rotate tests at gradually increasing rates.
# Server cleanup:
sudo nft delete table ip pingtun_probe_echo
```

Check that the server started and can read its private config before interpreting
missing replies. No valid responses produces a nonzero exit code. Expired or
unconfirmed requests include loss in either direction and cannot locate it.
`window_blocked_slots` and `schedule_missed_slots` separate local limits from
requested rate. Generated payload throughput is not encrypted application speed.

Avoid concurrent diagnostic clients sharing a key: their authenticated replies
can appear as invalid session traffic to one another. Use repeated interleaved
measurements: sequential A/B results on a changing path cannot establish whether
identifier mode, NAT, a provider or censorship caused loss.

# Install pingtun 0.4.1

[Русский](INSTALL.ru.md) · [Android details](android/README.md)

Examples target a Linux server with systemd, `iproute2`, `nftables` and a public
IPv4 address. Replace `203.0.113.10`, choose a private subnet that does not
conflict with your networks, and replace the server's Internet interface `eth0`.
One server instance serves one peer. Use separate keys, interface names and
subnets for additional instances. The guides configure only the named pingtun
interfaces/tables; the daemon itself does not configure your existing VPN.

## 1. Verify and install

Download the archive matching `uname -m` (`x86_64` = amd64, `aarch64` = arm64),
plus SHA256SUMS from the release. Verify **before** installing:

```sh
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf pingtun_0.4.1_linux_amd64.tar.gz
cd pingtun_0.4.1_linux_amd64
sudo install -m 755 bin/pingtun /usr/local/bin/pingtun
sudo install -d -m 755 /usr/local/libexec
sudo install -m 755 deploy/link-up.sh /usr/local/libexec/pingtun-link-up
sudo install -m 644 deploy/pingtun@.service /etc/systemd/system/
pingtun version
```

The same binary supports server and Linux client. It needs `/dev/net/tun`,
CAP_NET_ADMIN and normally CAP_NET_RAW. Android supplies its own TUN and uses
ICMP datagram sockets instead. On Linux, `socket_mode: ping` also avoids
CAP_NET_RAW for the carrier, but TUN administration still needs CAP_NET_ADMIN.

## 2. Generate a dedicated pair

```sh
pingtun init --server 203.0.113.10 --dir configs
# For an Android peer instead of the Linux client:
# pingtun mobile-init --server 203.0.113.10 --dir configs-phone --name Phone --address 10.203.0.2/30
```

New pairs use v2 and stable ICMP IDs. `init --legacy` selects v1. Removing the
`adaptive` object from an existing config also means v1; both endpoints must
match. The server authorizes the client's inner /32. Do not reuse another
client's private keys or connect two devices with the same profile.

Keep the generated files private (directories 0700, files 0600). Transfer only
`server.json` to the server and `client.json` to the Linux client, or
`profile.pingtun.json` privately to Android. Do not put any of them in a release.
Existing working configs/profiles do not need regeneration for 0.4.1.

## 3. Start the server and retain its TUN address across restarts

On the server, with `server.json` in the current directory:

```sh
sudo install -d -m 700 /etc/pingtun
sudo install -o root -g root -m 600 server.json /etc/pingtun/server.json
sudo install -d /etc/systemd/system/pingtun@server.service.d
sudo tee /etc/systemd/system/pingtun@server.service.d/address.conf >/dev/null <<'UNIT'
[Service]
ExecStartPost=/usr/local/libexec/pingtun-link-up pingtun0 10.203.0.1/30
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now pingtun@server
```

The helper waits for the daemon's TUN and sets only its address/link state.
If you change `interface` in JSON, also change the drop-in. Explicit root
ownership matters: an extracted archive may retain a different UID, and the
capability-confined root service cannot override a 0600 file's owner.

## 4. Forwarding, echo suppression and NAT on the server

Allow inbound IPv4 ICMP at the provider firewall and host firewall. Keep
management/SSH reachable. Create an **owned** firewall file, replacing `eth0`:

```nft
table ip pingtun_site {
 chain echo_guard {
  type filter hook output priority -5; policy accept;
  icmp type echo-reply @th,64,48 0x5054554e0201 drop
 }
 chain forward {
  type filter hook forward priority 0; policy accept;
  iifname "pingtun0" ip saddr != 10.203.0.2 drop
  iifname "pingtun0" oifname "eth0" accept
  iifname "pingtun0" drop
  oifname "pingtun0" ct state established,related accept
  oifname "pingtun0" drop
 }
 chain nat {
  type nat hook postrouting priority srcnat; policy accept;
  ip saddr 10.203.0.2 oifname "eth0" masquerade
 }
}
```

Save as `/etc/pingtun/site.nft`. This echo rule is for **v2**, preserves ordinary
ping and suppresses only reflected pingtun request frames. Use the supplied
`deploy/kernel-echo.nft` for v1 and `deploy/probe-kernel-echo.nft` for diagnostics.
An ACCEPT in a separate nft hook does not override another firewall's DROP;
if you use UFW, firewalld, Docker or other filter chains, allow these exact TUN
flows there too. The example permits access to routed networks on the server;
add destination restrictions if private networks must be excluded.

For persistence, enable forwarding in your chosen sysctl policy and create:

```sh
sudo tee /etc/sysctl.d/90-pingtun.conf >/dev/null <<'SYSCTL'
net.ipv4.ip_forward=1
SYSCTL
sudo sysctl -p /etc/sysctl.d/90-pingtun.conf
sudo nft -c -f /etc/pingtun/site.nft
sudo tee /etc/systemd/system/pingtun-firewall.service >/dev/null <<'UNIT'
[Unit]
Description=Owned pingtun firewall/NAT tables
After=network-pre.target
Before=pingtun@server.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/pingtun/site.nft
ExecStop=/usr/sbin/nft delete table ip pingtun_site
[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now pingtun-firewall
```

These are administrator-run examples. They do not change the main default route.
Use a unique table/service name for another peer. The nft table belongs only to
pingtun; never flush the whole machine's ruleset. Coordinate ordering with any
firewall manager that reloads or clears rules at boot.

## 5a. Linux client

Install the binary/unit/helper on the client too. Install the secret as
`/etc/pingtun/client.json` owned by root, mode 0600. Use an address drop-in for
`pingtun@client.service` with `10.203.0.2/30`, then enable/start that instance.
Verify the internal path with `ping -I pingtun0 10.203.0.1`.

For an opt-in per-source Internet test, choose an unused routing table/priority:

```sh
sudo ip route add unreachable default table 2050 metric 32760
sudo ip route add default dev pingtun0 table 2050 metric 10
sudo ip rule add pref 10050 from 10.203.0.2/32 lookup 2050
curl -4 --interface 10.203.0.2 https://api.ipify.org
```

This selects only traffic explicitly sourced from the tunnel address; it does
not redirect the whole workstation or preserve these route commands at reboot.
Keep the unreachable guard and configure persistent policy in your network
manager for continued use. A full gateway setup needs a separate reviewed
policy with LAN, management and public-endpoint exclusions. Preserve a direct
route to the ICMP server before changing any whole-machine default route.

## 5b. Android

Install `pingtun_0.4.1_android.apk`, transfer the **dedicated** profile privately
and select **Импортировать профиль** (Import profile). Grant VPN consent and
notifications; on GrapheneOS keep Network permission enabled. Tap **Подключить**
(Connect). The server must already be running for this exact peer identity.

Android routes all IPv4 through the TUN and captures/drops IPv6. During transport
recovery the TUN stays established. Enable Android's Always-on VPN and Block
connections without VPN if protection must survive app/service termination.
The optional screen-off mode holds a wake lock and uses more battery. App
network handoff and Doze still need longer device testing. The UI is Russian.
Updating the earlier APK in place retains the profile; do not uninstall first.
Keep the signing certificate unchanged for future updates.

## Check and roll back

`pingtun check --config ...` validates private config without printing secrets.
`run --stats-interval 5s` or SIGUSR1 emits key-free counters. See `journalctl -u
pingtun@server` and [LAB.md](LAB.md). Kernel reflections are not authenticated
success; multiple raw instances also see each other's differently keyed frames.

To roll back this example, stop/disable only its pingtun services, remove their
own drop-ins/table, and remove only routing rule 10050 and routes you added to
table 2050. Restore your previous forwarding setting if you changed it. Removing
a client VPN or routing policy changes where its traffic goes; preserve your
own fail-closed/management requirements when doing so. No live credentials or
private profiles are provided in the distribution.

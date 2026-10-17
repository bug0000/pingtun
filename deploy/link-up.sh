#!/bin/sh
# Called by an optional systemd per-instance drop-in after pingtun starts.
# Configures only an existing TUN; never edits routes, firewall or forwarding.
set -eu
if [ "$#" -ne 2 ]; then echo 'usage: pingtun-link-up INTERFACE IPv4/PREFIX' >&2; exit 2; fi
iface=$1
address=$2
case "$iface" in ''|*[!a-zA-Z0-9_-]*) echo 'invalid interface' >&2; exit 2;; esac
[ "${#iface}" -le 15 ] || exit 2
case "$address" in ''|*[!0-9./]*) echo 'invalid IPv4 prefix' >&2; exit 2;; esac
for attempt in $(seq 1 100); do
 if ip link show dev "$iface" >/dev/null 2>&1; then break; fi
 sleep .1
done
ip tuntap show dev "$iface" | grep -Eq "^$iface: tun( |$)" || { echo 'expected a TUN device' >&2; exit 1; }
ip address replace "$address" dev "$iface"
ip link set dev "$iface" up

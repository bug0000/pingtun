#!/usr/bin/env bash
# All network and mount mutations occur inside NEW user/network/mount namespaces.
# No sudo is used by this script, and no existing host interface is touched.
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
binary=$(realpath "${1:-$root/bin/pingtun}")
out=$(realpath -m "${2:-${TMPDIR:-/tmp}/pingtun-lab-$$}")
test -x "$binary"
mkdir -m 700 "$out" # Refuse to overwrite an existing run.
exec unshare -Urnm bash -euo pipefail -s -- "$root" "$binary" "$out" "${PINGTUN_LAB_MODE:-legacy}" "${PINGTUN_LAB_RAW:-1}" "${PINGTUN_LAB_ID_MODE:-stable}" "${PINGTUN_LAB_LOSS:-2%}" "${PINGTUN_LAB_BYTES:-262144}" "${PINGTUN_LAB_SOAK_SECONDS:-0}" <<'LAB'
root=$1 binary=$2 out=$3 mode=$4 raw=$5 id_mode=$6 loss=$7 payload_size=$8 soak=$9
[[ "$mode" == legacy || "$mode" == adaptive ]]
[[ "$id_mode" == stable || "$id_mode" == rotate ]]
[[ "$payload_size" =~ ^[0-9]+$ && "$payload_size" -ge 256 && "$payload_size" -le 16777216 ]]
[[ "$soak" =~ ^[0-9]+$ && "$soak" -le 600 ]]
mount --make-rprivate /
mount -t tmpfs tmpfs /run
cleanup() {
  set +e
  for ns in client router server; do
    for pid in $(ip netns pids "$ns" 2>/dev/null); do kill "$pid" 2>/dev/null; done
  done
  wait 2>/dev/null
  for ns in client router server; do ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT
for tool in ip nft tc python3 curl; do command -v "$tool" >/dev/null; done
for ns in client router server; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
ip link add c0 type veth peer name rc0
ip link set c0 netns client
ip link set rc0 netns router
ip link add s0 type veth peer name rs0
ip link set s0 netns server
ip link set rs0 netns router
ip -n client addr add 10.200.1.2/24 dev c0
ip -n router addr add 10.200.1.1/24 dev rc0
ip -n router addr add 192.0.2.1/24 dev rs0
ip -n server addr add 192.0.2.2/24 dev s0
ip -n client link set c0 up
ip -n router link set rc0 up
ip -n router link set rs0 up
ip -n server link set s0 up
ip -n client route add default via 10.200.1.1
ip -n server route add default via 192.0.2.1
ip netns exec router sysctl -qw net.ipv4.ip_forward=1
ip netns exec router nft -f - <<'NFT'
table ip lab_nat {
 chain postrouting { type nat hook postrouting priority srcnat; oifname "rs0" masquerade; }
}
table ip lab_filter {
 # nft 1.0.2 cannot infer widths for concatenated ICMP integer fields.
 # Pack ID+sequence into a test-only packet mark; this namespace has no mark rules.
 set seen { type ipv4_addr . mark; flags dynamic,timeout; timeout 5s; size 32768; }
 chain forward {
  type filter hook forward priority filter; policy drop;
  iifname "rs0" icmp type echo-reply meta mark set @th,32,32
  iifname "rs0" icmp type echo-reply ip saddr . meta mark @seen drop
  iifname "rs0" icmp type echo-reply update @seen { ip saddr . meta mark timeout 5s }
  ct state established,related accept
  iifname "rc0" oifname "rs0" accept
 }
}
NFT
ip netns exec server nft -f "$root/deploy/probe-kernel-echo.nft"
ip netns exec server nft -f "$root/deploy/kernel-echo.nft"
ip netns exec server nft -f "$root/deploy/adaptive-kernel-echo.nft"
ip netns exec router tc qdisc add dev rc0 root netem delay 20ms
ip netns exec router tc qdisc add dev rs0 root netem delay 20ms
"$binary" init --server 192.0.2.2 --dir "$out/configs"
if [[ "$raw" == 1 ]]; then
ip netns exec server "$binary" probe-server --config "$out/configs/server.json" --duration 100s --max-pps 5000 >"$out/probe-server.json" 2>"$out/probe-server.log" &
probe_pid=$!
sleep .2
for probe_id_mode in stable rotate; do
 for pps in 100 500 1000; do
  echo "probe: id=$probe_id_mode pps=$pps delay=40ms loss=0"
  ip netns exec client "$binary" probe --config "$out/configs/client.json" --duration 2s --timeout 300ms --pps "$pps" --id-mode "$probe_id_mode" >"$out/clean-$probe_id_mode-$pps.json"
 done
done
ip netns exec router tc qdisc replace dev rc0 root netem delay 20ms 5ms loss 2% reorder 10% 50%
ip netns exec router tc qdisc replace dev rs0 root netem delay 20ms 5ms loss 2% reorder 10% 50%
for probe_id_mode in stable rotate; do
 echo "probe: id=$probe_id_mode pps=500 delay+jitter loss=2% each direction reorder=10%"
 ip netns exec client "$binary" probe --config "$out/configs/client.json" --duration 2s --timeout 300ms --pps 500 --id-mode "$probe_id_mode" >"$out/impaired-$probe_id_mode.json"
done
kill -TERM "$probe_pid"
wait "$probe_pid"
python3 - "$out" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]); results=[]
for file in sorted(p.glob('clean-*.json'))+sorted(p.glob('impaired-*.json')):
 r=json.loads(file.read_text());r['case']=file.stem;results.append(r)
 assert r['verified']>0 and r['invalid']==0, r
 assert r['sent']==r['verified']+r['expired'], r
 assert r['peak_outstanding']<=256, r
 assert r['unconfirmed_percent']<40, r
 if file.name.startswith('clean-'): assert r['unconfirmed_percent']<5, r
(p/'probe-summary.json').write_text(json.dumps(results,indent=2)+'\n')
print('Raw ICMP NAT matrix passed: 8 cases.')
PY
fi
ip netns exec router tc qdisc replace dev rc0 root netem delay 20ms 5ms loss "$loss" reorder 10% 50%
ip netns exec router tc qdisc replace dev rs0 root netem delay 20ms 5ms loss "$loss" reorder 10% 50%
python3 - "$out" "$mode" "$id_mode" "$payload_size" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
for role in ('client','server'):
 f=p/'configs'/(role+'.json');c=json.loads(f.read_text());c['lanes']=2;c['window']=8;c['hold_ms']=500
 if sys.argv[2]=='adaptive':c['adaptive']={'id_mode':sys.argv[3],'max_pps':1000,'max_window':128,'idle_ms':500}
 f.write_text(json.dumps(c)+'\n');f.chmod(0o600)
size=int(sys.argv[4]);(p/'expected.bin').write_bytes((bytes(range(256))*((size+255)//256))[:size])
PY
ip netns exec server "$binary" run --config "$out/configs/server.json" >"$out/tunnel-server.log" 2>&1 &
server_pid=$!
ip netns exec client "$binary" run --config "$out/configs/client.json" >"$out/tunnel-client.log" 2>&1 &
client_pid=$!
for ns in server client; do
 for attempt in {1..100}; do ip -n "$ns" link show pingtun0 >/dev/null 2>&1 && break; sleep .05; done
 ip -n "$ns" link show pingtun0 >/dev/null
done
ip -n server address add 10.203.0.1/30 dev pingtun0
ip -n client address add 10.203.0.2/30 dev pingtun0
ip -n server link set pingtun0 up
ip -n client link set pingtun0 up
ip netns exec server python3 "$root/tests/http_fixture.py" --bytes "$payload_size" >"$out/http.log" 2>&1 &
sleep .2
echo 'Encrypted TUN: download/upload integrity with NAT, jitter, loss and reordering'
ip netns exec client curl --noproxy '*' --interface 10.203.0.2 --connect-timeout 10 --max-time 45 -fsS http://10.203.0.1:18089/payload -o "$out/download.bin" -w '%{json}\n' >"$out/download.json"
cmp "$out/expected.bin" "$out/download.bin"
ip netns exec client curl --noproxy '*' --interface 10.203.0.2 --connect-timeout 10 --max-time 45 -fsS --data-binary "@$out/expected.bin" http://10.203.0.1:18089/upload -o "$out/upload.sha256" -w '%{json}\n' >"$out/upload.json"
python3 - "$out" <<'PY'
import hashlib,sys
from pathlib import Path
p=Path(sys.argv[1]);assert hashlib.sha256((p/'expected.bin').read_bytes()).hexdigest()==(p/'upload.sha256').read_text().strip()
print('Encrypted payload checksums match in both directions.')
PY
if [[ "$mode" == adaptive ]]; then
 echo 'Adaptive: checking quiet traffic, blackout recovery and server restart'
 sleep .5
 kill -USR1 "$client_pid"
 sleep 1.2
 kill -USR1 "$client_pid"
 sleep .1
 python3 - "$out" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]);rows=[json.loads(s) for s in (p/'tunnel-client.log').read_text().splitlines() if s.startswith('{')]
assert len(rows)>=2, rows
idle=rows[-1]['wire_sent_bytes']-rows[-2]['wire_sent_bytes']
assert idle<8192, idle
(p/'idle.json').write_text(json.dumps({'interval_seconds':1.2,'client_wire_bytes':idle})+'\n')
print('Quiet interval: client sent',idle,'wire bytes in 1.2s.')
PY
 ip netns exec router nft -f - <<'NFT'
table ip blackout {
 chain forward {
  type filter hook forward priority -10; policy accept;
  ip protocol icmp drop
 }
}
NFT
 ip netns exec client curl --noproxy '*' --interface 10.203.0.2 --connect-timeout 15 --max-time 30 -fsS http://10.203.0.1:18089/payload -o "$out/recovered.bin" &
 transfer_pid=$!
 sleep 1.5
 ip netns exec router nft delete table ip blackout
 wait "$transfer_pid"
 cmp "$out/expected.bin" "$out/recovered.bin"
 kill -TERM "$server_pid"
 wait "$server_pid"
 ip netns exec server "$binary" run --config "$out/configs/server.json" >>"$out/tunnel-server.log" 2>&1 &
 server_pid=$!
 for attempt in {1..100}; do ip -n server link show pingtun0 >/dev/null 2>&1 && break; sleep .05; done
 ip -n server address add 10.203.0.1/30 dev pingtun0
 ip -n server link set pingtun0 up
 ip netns exec client curl --noproxy '*' --interface 10.203.0.2 --connect-timeout 15 --max-time 30 -fsS http://10.203.0.1:18089/payload -o "$out/restarted.bin"
 cmp "$out/expected.bin" "$out/restarted.bin"
fi
if [[ "$soak" -gt 0 ]]; then
 echo "Soak: repeated encrypted checksum checks for at least $soak seconds"
 soak_until=$((SECONDS+soak))
 while [[ "$SECONDS" -lt "$soak_until" ]]; do
  ip netns exec client curl --noproxy '*' --interface 10.203.0.2 --connect-timeout 10 --max-time 45 -fsS http://10.203.0.1:18089/payload -o "$out/soak.bin"
  cmp "$out/expected.bin" "$out/soak.bin"
  printf '%s %s\n' "$SECONDS" "$(ps -o rss= -p "$client_pid" | tr -d ' ')" >>"$out/soak.tsv"
 done
fi
kill -TERM "$client_pid" "$server_pid"
wait "$client_pid"
wait "$server_pid"
if [[ "$mode" == adaptive ]]; then
 python3 - "$out" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]);rows=[json.loads(s) for s in (p/'tunnel-client.log').read_text().splitlines() if s.startswith('{')]
r=rows[-1];assert r['peer_restarts']>=1, r
assert r['peak_outstanding']<=129, r
(p/'adaptive-summary.json').write_text(json.dumps(r,indent=2)+'\n')
print('Blackout and server restart recovered without restarting client.')
PY
fi
echo "Lab passed; private configs and results: $out"
LAB

#!/bin/sh
set -eu

velvetd=${1:?usage: netns-wg-admin-core.sh /path/to/velvetd}
test -x "${velvetd}" || { echo "velvetd is not executable: ${velvetd}" >&2; exit 2; }
test "$(id -u)" -eq 0 || { echo "netns E2E must run as root" >&2; exit 2; }
for command in ip wg ping python3 awk grep mktemp tr kill; do command -v "${command}" >/dev/null || { echo "missing command: ${command}" >&2; exit 2; }; done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
generator="${script_dir}/generate-wg-admin-core.py"
test -f "${generator}" || { echo "missing config generator: ${generator}" >&2; exit 2; }

suffix=$$
bridge="vwbr${suffix}"
runtime=$(mktemp -d /tmp/velvet-wg-admin-core.XXXXXXXX)
nodes="ea eb r1 r2 r3 xa xb xc"
pids=

namespace() { printf 'vw-%s-%s' "$1" "${suffix}"; }

diagnose() {
  for node in ${nodes}; do
    ns=$(namespace "${node}")
    test ! -f "${runtime}/${node}.log" || cat "${runtime}/${node}.log" >&2
    ip -n "${ns}" -details link show 2>/dev/null >&2 || true
    ip -n "${ns}" -details route show table all 2>/dev/null >&2 || true
    ip -n "${ns}" -6 -details route show table all 2>/dev/null >&2 || true
    ip -n "${ns}" -details rule show 2>/dev/null >&2 || true
    ip -n "${ns}" -6 -details rule show 2>/dev/null >&2 || true
  done
}

cleanup() {
  status=$?
  test "${status}" -eq 0 || diagnose
  for pid in ${pids}; do kill "${pid}" 2>/dev/null || true; done
  for node in ${nodes}; do ip netns del "$(namespace "${node}")" 2>/dev/null || true; done
  ip link del "${bridge}" 2>/dev/null || true
  rm -rf -- "${runtime}"
}
trap cleanup EXIT INT TERM

umask 077
wg genpsk >"${runtime}/fabric.psk"
for node in ${nodes}; do
  wg genkey >"${runtime}/${node}.key"
  wg pubkey <"${runtime}/${node}.key" >"${runtime}/${node}.pub"
done
python3 "${generator}" "${runtime}"

ip link add "${bridge}" type bridge
ip link set "${bridge}" up

index=0
for item in \
  "ea:192.0.2.11" "eb:192.0.2.12" \
  "r1:192.0.2.21" "r2:192.0.2.22" "r3:192.0.2.23" \
  "xa:192.0.2.31" "xb:192.0.2.32" "xc:192.0.2.33"; do
  node=${item%%:*}
  address=${item#*:}
  ns=$(namespace "${node}")
  index=$((index + 1))
  root_if="vwr${index}-${suffix}"
  node_if="vwn${index}-${suffix}"
  ip netns add "${ns}"
  ip link add "${root_if}" type veth peer name "${node_if}"
  ip link set "${root_if}" master "${bridge}"
  ip link set "${root_if}" up
  ip link set "${node_if}" netns "${ns}"
  ip -n "${ns}" link set lo up
  ip -n "${ns}" link set "${node_if}" name underlay0
  ip -n "${ns}" address add "${address}/24" dev underlay0
  ip -n "${ns}" link set underlay0 up
done

add_attached() {
  node=$1
  interface=$2
  shift 2
  ns=$(namespace "${node}")
  ip -n "${ns}" link add "${interface}" type dummy
  for address in "$@"; do ip -n "${ns}" address add "${address}" dev "${interface}"; done
  ip -n "${ns}" link set "${interface}" up
}

# Access and service networks are deliberately external to Velvet. They model
# wg-admin's device pools, translated NAT resources, and egress announcements.
add_attached ea access0 10.100.30.1/24
add_attached eb access0 10.100.31.1/24 10.100.32.1/24
add_attached xa service0 10.60.1.1/24 10.61.1.1/24 10.100.201.1/24
add_attached xb service0 10.60.2.1/24 10.100.202.1/24
add_attached xc service0 10.60.3.1/24

for node in ${nodes}; do
  ns=$(namespace "${node}")
  ip netns exec "${ns}" "${velvetd}" --config "${runtime}/${node}.json" --once >"${runtime}/${node}.log" 2>&1 &
  pids="${pids} $!"
done

attempt=0
while :; do
  alive=0
  for pid in ${pids}; do kill -0 "${pid}" 2>/dev/null && alive=1; done
  test "${alive}" -eq 1 || break
  attempt=$((attempt + 1))
  if test "${attempt}" -ge 60; then
    echo "complex Core topology did not establish every Link" >&2
    exit 1
  fi
  sleep 1
done
for pid in ${pids}; do wait "${pid}"; done
pids=

for item in "ea:2" "eb:2" "r1:3" "r2:4" "r3:2" "xa:1" "xb:1" "xc:1"; do
  node=${item%%:*}
  expected=${item#*:}
  actual=$(grep -c '"event":"velvet-link-established"' "${runtime}/${node}.log" || true)
  test "${actual}" -eq "${expected}" || { echo "${node}: established ${actual} Links, want ${expected}" >&2; exit 1; }
done

ns_ea=$(namespace ea)
ns_eb=$(namespace eb)

# Plan A: two Access sources, two exits, and two translated NAT resources.
ip netns exec "${ns_ea}" ping -c 1 -W 3 -I 10.100.30.1 10.60.1.1 >/dev/null
ip netns exec "${ns_ea}" ping -c 1 -W 3 -I 10.100.30.1 10.60.2.1 >/dev/null
ip netns exec "${ns_ea}" ping -c 1 -W 3 -I 10.100.30.1 10.100.201.1 >/dev/null
ip netns exec "${ns_ea}" ping -c 1 -W 3 -I 10.100.30.1 10.100.202.1 >/dev/null
ip netns exec "${ns_eb}" ping -c 1 -W 3 -I 10.100.32.1 10.60.1.1 >/dev/null
ip netns exec "${ns_eb}" ping -c 1 -W 3 -I 10.100.32.1 10.60.2.1 >/dev/null

# Plan B shares entry-b and exit-b with Plan A but reaches a third exit and a
# different prefix on exit-a.
ip netns exec "${ns_eb}" ping -c 1 -W 3 -I 10.100.31.1 10.60.2.1 >/dev/null
ip netns exec "${ns_eb}" ping -c 1 -W 3 -I 10.100.31.1 10.60.3.1 >/dev/null
ip netns exec "${ns_eb}" ping -c 1 -W 3 -I 10.100.31.1 10.61.1.1 >/dev/null

ping_blocked() {
  ns=$1
  source=$2
  target=$3
  if ip netns exec "${ns}" ping -c 1 -W 1 -I "${source}" "${target}" >/dev/null 2>&1; then
    echo "unexpected connectivity: ${ns} ${source} -> ${target}" >&2
    exit 1
  fi
}
ping_blocked "${ns_ea}" 10.100.30.1 10.60.3.1
ping_blocked "${ns_ea}" 10.100.30.1 10.61.1.1
ping_blocked "${ns_eb}" 10.100.31.1 10.60.1.1

# Inspect representative shortest-path, table-isolation, return, and local
# exception state rather than relying only on end-to-end reachability.
ip -n "$(namespace r2)" route show table 20030 exact 10.60.1.0/24 dev vl-r2-r1 proto 201 | grep -q 10.60.1.0/24
ip -n "$(namespace r2)" route show table 20030 exact 10.60.2.0/24 dev vl-r2-xb proto 201 | grep -q 10.60.2.0/24
ip -n "$(namespace r1)" route show table 20031 exact 10.60.3.0/24 dev vl-r1-r2 proto 201 | grep -q 10.60.3.0/24
ip -n "${ns_eb}" route show table 20030 exact 10.60.1.0/24 dev vl-eb-r2 proto 201 | grep -q 10.60.1.0/24
ip -n "${ns_eb}" route show table 20031 exact 10.61.1.0/24 dev vl-eb-r2 proto 201 | grep -q 10.61.1.0/24
test -z "$(ip -n "${ns_eb}" route show table 20031 exact 10.60.1.0/24)"
ip -n "$(namespace xa)" route show table 20030 type throw exact 10.60.1.0/24 proto 201 | grep -q 10.60.1.0/24
ip -n "$(namespace xa)" route show table 20031 type throw exact 10.61.1.0/24 proto 201 | grep -q 10.61.1.0/24
ip -n "${ns_eb}" -details rule show | grep -q 'from 10.100.32.0/24 lookup 20030 proto 201'
ip -n "${ns_eb}" -details rule show | grep -q 'from 10.100.31.0/24 lookup 20031 proto 201'

# Full-Fabric Core routes are independent from either Plan.
ip netns exec "${ns_ea}" ping -6 -c 1 -W 3 fd78:abcd::8 >/dev/null
ip -n "${ns_ea}" -6 route show table 20000 exact fd78:abcd::8/128 dev vl-ea-r2 proto 201 | grep -q fd78:abcd::8

echo "velvet wg-admin complex multi-Plan Core E2E: PASS"

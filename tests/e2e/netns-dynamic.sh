#!/bin/sh
set -eu

velvetd=${1:?usage: netns-dynamic.sh /path/to/velvetd /path/to/babel-rs /path/to/velvetctl}
babel_rs=${2:?usage: netns-dynamic.sh /path/to/velvetd /path/to/babel-rs /path/to/velvetctl}
velvetctl=${3:?usage: netns-dynamic.sh /path/to/velvetd /path/to/babel-rs /path/to/velvetctl}
test -x "${velvetd}" || { echo "velvetd is not executable: ${velvetd}" >&2; exit 2; }
test -x "${babel_rs}" || { echo "babel-rs is not executable: ${babel_rs}" >&2; exit 2; }
test -x "${velvetctl}" || { echo "velvetctl is not executable: ${velvetctl}" >&2; exit 2; }
test "$(id -u)" -eq 0 || { echo "netns E2E must run as root" >&2; exit 2; }
for command in ip wg ping python3 grep mktemp kill awk; do command -v "${command}" >/dev/null || { echo "missing command: ${command}" >&2; exit 2; }; done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
generator="${script_dir}/generate-dynamic-core.py"
suffix=$$
bridge="vdbr${suffix}"
runtime=$(mktemp -d /tmp/velvet-dynamic.XXXXXXXX)
nodes="ea eb r1 r2 r3 xa xb xc"
pids=

namespace() { printf 'vd-%s-%s' "$1" "${suffix}"; }
uuid() {
  case $1 in
    ea) index=1;; eb) index=2;; r1) index=3;; r2) index=4;;
    r3) index=5;; xa) index=6;; xb) index=7;; xc) index=8;;
  esac
  printf '20000000-0000-4000-8000-%012d' "${index}"
}
loopback_index() {
  case $1 in
    ea) echo 1;; eb) echo 2;; r1) echo 3;; r2) echo 4;;
    r3) echo 5;; xa) echo 6;; xb) echo 7;; xc) echo 8;;
  esac
}
diagnose() {
  for node in ${nodes}; do
    ns=$(namespace "${node}")
    test ! -f "${runtime}/${node}.log" || tail -n 160 "${runtime}/${node}.log" >&2
    ip -n "${ns}" -details rule show >&2 2>/dev/null || true
    ip -n "${ns}" -6 -details rule show >&2 2>/dev/null || true
    ip -n "${ns}" -details route show table all >&2 2>/dev/null || true
    ip -n "${ns}" -6 -details route show table all >&2 2>/dev/null || true
  done
}
cleanup() {
  status=$?
  test "${status}" -eq 0 || diagnose
  for pid in ${pids}; do kill -TERM "${pid}" 2>/dev/null || true; done
  sleep 1
  for node in ${nodes}; do
    ip netns del "$(namespace "${node}")" 2>/dev/null || true
    rm -rf -- "/run/velvet/$(uuid "${node}")" "/var/lib/velvet/$(uuid "${node}")"
  done
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
python3 "${generator}" "${runtime}" "${babel_rs}"

# This milestone must contain no operator-configured static multi-hop routes.
if grep -q '"routes"' "${runtime}"/*.json; then
  echo "dynamic NodeSpec unexpectedly contains static routes" >&2
  exit 1
fi

ip link add "${bridge}" type bridge
ip link set "${bridge}" up
index=0
for item in \
  "ea:192.0.2.11" "eb:192.0.2.12" \
  "r1:192.0.2.21" "r2:192.0.2.22" "r3:192.0.2.23" \
  "xa:192.0.2.31" "xb:192.0.2.32" "xc:192.0.2.33"; do
  node=${item%%:*}; address=${item#*:}; ns=$(namespace "${node}")
  index=$((index + 1)); root_if="vdr${index}-${suffix}"; node_if="vdn${index}-${suffix}"
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
  node=$1; interface=$2; shift 2; ns=$(namespace "${node}")
  ip -n "${ns}" link add "${interface}" type dummy
  for address in "$@"; do ip -n "${ns}" address add "${address}" dev "${interface}"; done
  ip -n "${ns}" link set "${interface}" up
}
add_attached ea access0 10.100.30.1/24
add_attached eb access0 10.100.31.1/24 10.100.32.1/24
add_attached xa service0 10.60.1.1/24 10.61.1.1/24 10.100.201.1/24
add_attached xb service0 10.60.2.1/24 10.100.202.1/24
add_attached xc service0 10.60.3.1/24

for node in ${nodes}; do
  ns=$(namespace "${node}")
  ip netns exec "${ns}" "${velvetd}" --config "${runtime}/${node}.json" --reconcile-interval 5s >"${runtime}/${node}.log" 2>&1 &
  pid=$!
  printf '%s\n' "${pid}" >"${runtime}/${node}.pid"
  pids="${pids} ${pid}"
done

wait_babel() {
  node=$1; attempt=0
  while :; do
    grep -q '"event":"babel-rs","status":"running"' "${runtime}/${node}.log" 2>/dev/null && return
    attempt=$((attempt + 1))
    test "${attempt}" -lt 30 || { echo "${node}: managed babel-rs did not start" >&2; exit 1; }
    sleep 1
  done
}
for node in ${nodes}; do wait_babel "${node}"; done

attempt=0
while :; do
  ip netns exec "$(namespace ea)" "${velvetctl}" status --config "${runtime}/ea.json" >"${runtime}/ea.status"
  grep -q '"ready":true' "${runtime}/ea.status" && break
  attempt=$((attempt + 1)); test "${attempt}" -lt 30 || { echo "velvetd did not become ready" >&2; exit 1; }; sleep 1
done
grep -q '"state":"running"' "${runtime}/ea.status"

# Exactly one velvetd owns a network namespace.
if ip netns exec "$(namespace ea)" "${velvetd}" --config "${runtime}/ea.json" --once >"${runtime}/second.log" 2>&1; then
  echo "a second velvetd unexpectedly acquired the namespace" >&2
  exit 1
fi
grep -q 'another velvetd already owns this network namespace' "${runtime}/second.log"

wait_ping6() {
  node=$1; target=$2; ns=$(namespace "${node}"); attempt=0
  while ! ip netns exec "${ns}" ping -6 -c 1 -W 1 -I "fd78:abcd::$(loopback_index "${node}")" "${target}" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    test "${attempt}" -lt 60 || { echo "${node}: loopback ${target} did not converge" >&2; exit 1; }
    sleep 1
  done
}

# Every generated node loopback must become reachable across the dynamic RIB.
for source in ${nodes}; do
  for index in 1 2 3 4 5 6 7 8; do wait_ping6 "${source}" "fd78:abcd::${index}"; done
done

for node in ${nodes}; do
  ip -n "$(namespace "${node}")" -o -6 addr show dev vv-loop scope global | grep -q 'fd78:abcd::'
done

# Invalid NodeSpec reload is rejected without disturbing the active generation;
# restoring the complete candidate then commits a new generation.
cp "${runtime}/ea.json" "${runtime}/ea.valid.json"
printf '{ invalid json\n' >"${runtime}/ea.json"
if ip netns exec "$(namespace ea)" "${velvetctl}" reload --config "${runtime}/ea.valid.json" >"${runtime}/invalid-reload.log" 2>&1; then
  echo "invalid NodeSpec reload unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'reload_rejected' "${runtime}/invalid-reload.log"
cp "${runtime}/ea.valid.json" "${runtime}/ea.json.new"
mv "${runtime}/ea.json.new" "${runtime}/ea.json"
ip netns exec "$(namespace ea)" "${velvetctl}" reload --config "${runtime}/ea.json" >"${runtime}/valid-reload.log"
ip netns exec "$(namespace ea)" "${velvetctl}" status --config "${runtime}/ea.json" | grep -q '"config_generation":2'
wait_ping6 ea fd78:abcd::8

# Killing only the managed child must produce a non-zero exit, supervisor
# backoff, a new ready child, and restored routes without restarting velvetd.
parent_ea=$(cat "${runtime}/ea.pid")
child_ea=
for candidate in $(ip netns pids "$(namespace ea)"); do
  if test "$(cat "/proc/${candidate}/comm")" = babel-rs; then child_ea=${candidate}; break; fi
done
test -n "${child_ea}" || { echo "ea babel-rs child was not found" >&2; exit 1; }
kill -KILL "${child_ea}"
attempt=0
running_count=$(grep -c '"event":"babel-rs","status":"running"' "${runtime}/ea.log" || true)
while test "${running_count}" -lt 3; do
  attempt=$((attempt + 1)); test "${attempt}" -lt 45 || { echo "babel-rs child was not restarted" >&2; exit 1; }; sleep 1
  running_count=$(grep -c '"event":"babel-rs","status":"running"' "${runtime}/ea.log" || true)
done
kill -0 "${parent_ea}"
wait_ping6 ea fd78:abcd::8

# Access is outside Velvet Core. These destination selectors model the small
# external integration hook needed for return traffic; all routes in the
# selected tables are still learned through Babel.
for node in ${nodes}; do
  ns=$(namespace "${node}")
  ip -n "${ns}" rule add priority 19930 to 10.100.30.0/24 lookup 20030
  ip -n "${ns}" rule add priority 19930 to 10.100.32.0/24 lookup 20030
  ip -n "${ns}" rule add priority 19931 to 10.100.31.0/24 lookup 20031
done

wait_ping4() {
  node=$1; source=$2; target=$3; ns=$(namespace "${node}"); attempt=0
  while ! ip netns exec "${ns}" ping -c 1 -W 1 -I "${source}" "${target}" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    test "${attempt}" -lt 45 || { echo "${node}: ${source} -> ${target} did not converge" >&2; exit 1; }
    sleep 1
  done
}
wait_ping4 ea 10.100.30.1 10.60.1.1
wait_ping4 ea 10.100.30.1 10.60.2.1
wait_ping4 eb 10.100.32.1 10.100.201.1
wait_ping4 eb 10.100.31.1 10.60.3.1
wait_ping4 eb 10.100.31.1 10.61.1.1

# Representative routes must be Babel-owned and genuinely multi-hop.
ip -n "$(namespace ea)" -6 route show table 20000 exact fd78:abcd::8/128 proto 203 | grep -q fd78:abcd::8
ip -n "$(namespace ea)" route show table 20030 exact 10.60.2.0/24 proto 203 | grep -q 10.60.2.0/24
ip -n "$(namespace eb)" route show table 20031 exact 10.61.1.0/24 proto 203 | grep -q 10.61.1.0/24
ip -n "$(namespace eb)" -details rule show | grep -q 'from 10.100.32.0/24 lookup 20030 proto 201'

wait_route8() {
  presence=$1; attempt=0
  while :; do
    route=$(ip -n "$(namespace ea)" -6 route show table 20000 exact fd78:abcd::8/128 proto 203 2>/dev/null || true)
    if { test "${presence}" = present && test -n "${route}"; } || { test "${presence}" = absent && test -z "${route}"; }; then return; fi
    attempt=$((attempt + 1))
    test "${attempt}" -lt 50 || { echo "xc route did not become ${presence}" >&2; exit 1; }
    sleep 1
  done
}

# Stopping the managed leaf withdraws its origins; restarting the same
# velvetd/babel-rs pair must restore Router-ID state and reconverge.
pid_xc=$(cat "${runtime}/xc.pid")
kill -TERM "${pid_xc}"
wait "${pid_xc}" || true
wait_route8 absent
ip netns exec "$(namespace xc)" "${velvetd}" --config "${runtime}/xc.json" --reconcile-interval 5s >>"${runtime}/xc.log" 2>&1 &
pid_xc=$!
printf '%s\n' "${pid_xc}" >"${runtime}/xc.pid"
pids="${pids} ${pid_xc}"
wait_route8 present
wait_ping6 ea fd78:abcd::8

echo "velvet managed babel-rs dynamic multi-Plan Core E2E: PASS"

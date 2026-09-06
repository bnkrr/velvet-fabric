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
. "${script_dir}/core-topology.sh"
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
    echo "--- ${node}: status and Dynamic Link events ---" >&2
    test ! -f "${runtime}/${node}.dynamic-status" || cat "${runtime}/${node}.dynamic-status" >&2
    test ! -f "${runtime}/${node}.log" || grep -E 'velvet-dynamic|panic|no such device|counterproposal' "${runtime}/${node}.log" | tail -n 100 >&2 || true
    ip netns exec "${ns}" wg show >&2 2>/dev/null || true
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
create_core_keys
python3 "${generator}" "${runtime}" "${babel_rs}"

# This milestone must contain no operator-configured static multi-hop routes.
if grep -q '"routes"' "${runtime}"/*.json; then
  echo "dynamic NodeSpec unexpectedly contains static routes" >&2
  exit 1
fi

create_core_underlay vd

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
  for index in 1 2 3 4 5 6 7 8; do
    [ "${index}" = "$(loopback_index "${source}")" ] && continue
    wait_ping6 "${source}" "fd78:abcd::${index}"
  done
done

for node in ${nodes}; do
  ip -n "$(namespace "${node}")" -o -6 addr show dev vv-loop scope global | grep -q 'fd78:abcd::'
done

# Invalid NodeSpec reload is rejected without disturbing the active generation;
# reloading an equivalent effective config preserves the same generation.
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
ip netns exec "$(namespace ea)" "${velvetctl}" status --config "${runtime}/ea.json" | grep -q '"config_generation":1'
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
while test "${running_count}" -lt 2; do
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
    # A graceful retraction normally converges immediately.  The upper bound
    # also covers expiry after a lost UDP retraction (3.5 x the 16s Update
    # interval), which is part of Babel's normal recovery path.
    test "${attempt}" -lt 70 || { echo "xc route did not become ${presence}" >&2; exit 1; }
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

# Restart the same sparse Core with Dynamic Link enabled. No static multi-hop
# route is added: routed VFP discovers each remote Node UID, observations from
# the existing Links provide the underlay candidate, and every missing pair
# must become a directly connected runtime Link.
for node in ${nodes}; do
  pid=$(cat "${runtime}/${node}.pid")
  kill -TERM "${pid}"
done
for node in ${nodes}; do
  pid=$(cat "${runtime}/${node}.pid")
  wait "${pid}" || true
done
pids=
python3 "${generator}" "${runtime}" "${babel_rs}" dynamic-links
if grep -q '"routes"' "${runtime}"/*.json; then
  echo "Dynamic Link NodeSpec unexpectedly contains static routes" >&2
  exit 1
fi
for node in ${nodes}; do
  ns=$(namespace "${node}")
  ip netns exec "${ns}" "${velvetd}" --config "${runtime}/${node}.json" --reconcile-interval 5s >>"${runtime}/${node}.log" 2>&1 &
  pid=$!
  printf '%s\n' "${pid}" >"${runtime}/${node}.pid"
  pids="${pids} ${pid}"
done

expected_dynamic_links() {
  case $1 in
    ea|eb) echo 5;;
    r1) echo 4;;
    r2) echo 3;;
    r3) echo 5;;
    xa|xb|xc) echo 6;;
  esac
}
wait_dynamic_links() {
  node=$1; expected=$(expected_dynamic_links "${node}"); attempt=0
  while :; do
    ip netns exec "$(namespace "${node}")" "${velvetctl}" status --config "${runtime}/${node}.json" >"${runtime}/${node}.dynamic-status" 2>/dev/null || true
    grep -q "\"dynamic_links\":${expected}" "${runtime}/${node}.dynamic-status" 2>/dev/null && return
    attempt=$((attempt + 1))
    test "${attempt}" -lt 120 || { echo "${node}: expected ${expected} dynamic Links" >&2; exit 1; }
    sleep 1
  done
}
for node in ${nodes}; do wait_dynamic_links "${node}"; done

# xc is passive in the generated NodeSpec: active peers must build all six
# missing Links toward it, while xc must never originate a Proposal itself.
if grep -q '"event":"velvet-dynamic-attempt","status":"proposed"' "${runtime}/xc.log"; then
  echo "xc: passive Dynamic Link mode originated a Proposal" >&2
  exit 1
fi
grep -q '"event":"velvet-dynamic-attempt","status":"accepted"' "${runtime}/xc.log"

# A complete eight-node mesh has seven Babel interfaces at every node: its
# original static neighbors plus all complementary Dynamic Links. Interface
# glob reconciliation is asynchronous with respect to VFP Link commit.
wait_babel_mesh() {
  node=$1; attempt=0
  while :; do
    ip netns exec "$(namespace "${node}")" "${velvetctl}" status --config "${runtime}/${node}.json" >"${runtime}/${node}.dynamic-status"
    grep -q '"attached_interfaces":7' "${runtime}/${node}.dynamic-status" && return
    attempt=$((attempt + 1))
    test "${attempt}" -lt 60 || { echo "${node}: babel-rs did not attach all seven mesh interfaces" >&2; exit 1; }
    sleep 1
  done
}
for node in ${nodes}; do
  wait_babel_mesh "${node}"
  interfaces=$(ip netns exec "$(namespace "${node}")" wg show interfaces)
  set -- ${interfaces}
  dynamic_count=0
  for interface in "$@"; do
    case ${interface} in vdl-*) dynamic_count=$((dynamic_count + 1));; esac
  done
  test "$#" -eq 7 && test "${dynamic_count}" -eq "$(expected_dynamic_links "${node}")" || {
    echo "${node}: unexpected kernel mesh interfaces: ${interfaces}" >&2
    exit 1
  }
done

# The Dynamic Link contributes an adjacent loopback route, and Babel exports
# domain reachability over that new interface. End-to-end loopback and Plan
# traffic must remain converged after the topology changes from sparse to mesh.
wait_route_device() {
  family=$1; table=$2; prefix=$3; protocol=$4; device=$5; attempt=0
  while :; do
    route=$(ip -n "$(namespace ea)" "${family}" route show table "${table}" exact "${prefix}" proto "${protocol}")
    echo "${route}" | grep -q "dev ${device}" && return
    attempt=$((attempt + 1))
    test "${attempt}" -lt 60 || {
      echo "ea: ${prefix} did not converge to ${device}: ${route}" >&2
      exit 1
    }
    sleep 1
  done
}
wait_route_device -6 20000 fd78:abcd::8/128 202 vdl-xc-2000
wait_route_device -4 20030 10.60.2.0/24 203 vdl-xb-2000
echo "Dynamic Link mesh routes: PASS"
for source in ${nodes}; do
  for index in 1 2 3 4 5 6 7 8; do
    [ "${index}" = "$(loopback_index "${source}")" ] && continue
    wait_ping6 "${source}" "fd78:abcd::${index}"
  done
done
wait_ping4 ea 10.100.30.1 10.60.2.1
wait_ping4 eb 10.100.31.1 10.60.3.1
echo "Dynamic Link mesh connectivity: PASS"

# An equivalent effective reload is a no-op and therefore preserves learned
# Dynamic Links rather than deleting and relearning them.
before=$(ip -n "$(namespace ea)" -o link show vdl-xc-2000 | awk -F: '{print $1}')
ip netns exec "$(namespace ea)" "${velvetctl}" reload --config "${runtime}/ea.json" >"${runtime}/dynamic-reload.log"
ip netns exec "$(namespace ea)" "${velvetctl}" status --config "${runtime}/ea.json" >"${runtime}/ea.dynamic-status"
grep -q '"config_generation":1' "${runtime}/ea.dynamic-status"
grep -q '"dynamic_links":5' "${runtime}/ea.dynamic-status"
after=$(ip -n "$(namespace ea)" -o link show vdl-xc-2000 | awk -F: '{print $1}')
test "${before}" = "${after}"
echo "Dynamic Link equivalent reload preservation: PASS"

echo "velvet managed babel-rs dynamic routing and Dynamic Link mesh E2E: PASS"

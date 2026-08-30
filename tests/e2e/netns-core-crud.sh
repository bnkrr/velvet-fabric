#!/bin/sh
set -eu

velvetd=${1:?usage: netns-core-crud.sh /path/to/velvetd}
test -x "${velvetd}" || { echo "velvetd is not executable: ${velvetd}" >&2; exit 2; }
test "$(id -u)" -eq 0 || { echo "netns E2E must run as root" >&2; exit 2; }
for command in ip wg ping awk grep mktemp tr wc cut kill; do command -v "${command}" >/dev/null || { echo "missing command: ${command}" >&2; exit 2; }; done

suffix=$$
ns_a="vc-a-${suffix}"
ns_b="vc-b-${suffix}"
ns_c="vc-c-${suffix}"
bridge="vc-br-${suffix}"
runtime=$(mktemp -d /tmp/velvet-core-crud.XXXXXXXX)
pid_a=
pid_b=
pid_c=

diagnose_namespace() {
  namespace=$1
  ip -n "${namespace}" -details link show 2>/dev/null >&2 || true
  ip -n "${namespace}" -details route show table all 2>/dev/null >&2 || true
  ip -n "${namespace}" -6 -details route show table all 2>/dev/null >&2 || true
  ip -n "${namespace}" -details rule show 2>/dev/null >&2 || true
  ip -n "${namespace}" -6 -details rule show 2>/dev/null >&2 || true
}

cleanup() {
  status=$?
  if test "${status}" -ne 0; then
    for log_file in "${runtime}"/*.log; do test ! -f "${log_file}" || cat "${log_file}" >&2; done
    diagnose_namespace "${ns_a}"
    diagnose_namespace "${ns_b}"
    diagnose_namespace "${ns_c}"
  fi
  test -z "${pid_a}" || kill "${pid_a}" 2>/dev/null || true
  test -z "${pid_b}" || kill "${pid_b}" 2>/dev/null || true
  test -z "${pid_c}" || kill "${pid_c}" 2>/dev/null || true
  ip netns del "${ns_a}" 2>/dev/null || true
  ip netns del "${ns_b}" 2>/dev/null || true
  ip netns del "${ns_c}" 2>/dev/null || true
  ip link del "ra-${suffix}" 2>/dev/null || true
  ip link del "rb-${suffix}" 2>/dev/null || true
  ip link del "rc-${suffix}" 2>/dev/null || true
  ip link del "${bridge}" 2>/dev/null || true
  rm -rf -- "${runtime}"
}
trap cleanup EXIT INT TERM

wait_cluster() {
  attempt=0
  while kill -0 "${pid_a}" 2>/dev/null || kill -0 "${pid_b}" 2>/dev/null || kill -0 "${pid_c}" 2>/dev/null; do
    attempt=$((attempt + 1))
    if test "${attempt}" -ge 40; then
      echo "velvetd cluster did not establish every Link" >&2
      return 1
    fi
    sleep 1
  done
  wait "${pid_a}"
  wait "${pid_b}"
  wait "${pid_c}"
  pid_a=
  pid_b=
  pid_c=
}

start_cluster() {
  a_config=$1
  run_name=$2
  ip netns exec "${ns_a}" "${velvetd}" --config "${a_config}" --once >"${runtime}/a-${run_name}.log" 2>&1 &
  pid_a=$!
  ip netns exec "${ns_b}" "${velvetd}" --config "${runtime}/b.json" --once >"${runtime}/b-${run_name}.log" 2>&1 &
  pid_b=$!
  ip netns exec "${ns_c}" "${velvetd}" --config "${runtime}/c.json" --once >"${runtime}/c-${run_name}.log" 2>&1 &
  pid_c=$!
  wait_cluster
}

umask 077
wg genkey >"${runtime}/a.key"
wg genkey >"${runtime}/b.key"
wg genkey >"${runtime}/c.key"
wg pubkey <"${runtime}/a.key" >"${runtime}/a.pub"
wg pubkey <"${runtime}/b.key" >"${runtime}/b.pub"
wg pubkey <"${runtime}/c.key" >"${runtime}/c.pub"
wg genpsk >"${runtime}/fabric.psk"
a_private=$(tr -d '\n' <"${runtime}/a.key")
b_private=$(tr -d '\n' <"${runtime}/b.key")
c_private=$(tr -d '\n' <"${runtime}/c.key")
a_public=$(tr -d '\n' <"${runtime}/a.pub")
b_public=$(tr -d '\n' <"${runtime}/b.pub")
c_public=$(tr -d '\n' <"${runtime}/c.pub")
fabric_psk=$(tr -d '\n' <"${runtime}/fabric.psk")

ip netns add "${ns_a}"
ip netns add "${ns_b}"
ip netns add "${ns_c}"
ip link add "${bridge}" type bridge
ip link set "${bridge}" up

ip link add "ra-${suffix}" type veth peer name "na-${suffix}"
ip link add "rb-${suffix}" type veth peer name "nb-${suffix}"
ip link add "rc-${suffix}" type veth peer name "nc-${suffix}"
ip link set "ra-${suffix}" master "${bridge}"
ip link set "rb-${suffix}" master "${bridge}"
ip link set "rc-${suffix}" master "${bridge}"
ip link set "ra-${suffix}" up
ip link set "rb-${suffix}" up
ip link set "rc-${suffix}" up
ip link set "na-${suffix}" netns "${ns_a}"
ip link set "nb-${suffix}" netns "${ns_b}"
ip link set "nc-${suffix}" netns "${ns_c}"
ip -n "${ns_a}" link set "na-${suffix}" name underlay0
ip -n "${ns_b}" link set "nb-${suffix}" name underlay0
ip -n "${ns_c}" link set "nc-${suffix}" name underlay0
ip -n "${ns_a}" link set lo up
ip -n "${ns_b}" link set lo up
ip -n "${ns_c}" link set lo up
ip -n "${ns_a}" address add 192.0.2.1/24 dev underlay0
ip -n "${ns_b}" address add 192.0.2.2/24 dev underlay0
ip -n "${ns_c}" address add 192.0.2.3/24 dev underlay0
ip -n "${ns_a}" link set underlay0 up
ip -n "${ns_b}" link set underlay0 up
ip -n "${ns_c}" link set underlay0 up

ip -n "${ns_a}" link add access0 type dummy
ip -n "${ns_a}" address add 10.100.1.1/24 dev access0
ip -n "${ns_a}" link set access0 up
ip -n "${ns_c}" link add service0 type dummy
ip -n "${ns_c}" address add 192.168.20.1/24 dev service0
ip -n "${ns_c}" link set service0 up

cat >"${runtime}/a.json" <<EOF
{
  "api_version": "velvet.io/v1alpha1",
  "kind": "NodeSpec",
  "fabric": {
    "psk": "${fabric_psk}",
    "link_prefix_v4": "10.240.0.0/16",
    "link_prefix_v6": "fd77::/48",
    "loopback_prefix_v6": "fd78:1234:5678::/48",
    "routing_table_id": 20000,
    "routes": {"b": ["fd78:1234:5678::3/128"]}
  },
  "node": {
    "uid": {"name": "a", "uuid": "10000000-0000-4000-8000-000000000001"},
    "private_key": "${a_private}",
    "loopback_address_v6": "fd78:1234:5678::1"
  },
  "peers": [{
    "name": "b",
    "public_key": "${b_public}",
    "endpoints": ["192.0.2.2:51002"],
    "listen_port": 51001,
    "interface_name": "vl-a-b"
  }],
  "domains": {
    "production": {
      "table_id": 20001,
      "source_prefixes": ["10.100.1.0/24"],
      "routes": {"b": ["192.168.20.0/24"]},
      "announcements": ["10.100.1.0/24"]
    }
  }
}
EOF

cat >"${runtime}/b.json" <<EOF
{
  "api_version": "velvet.io/v1alpha1",
  "kind": "NodeSpec",
  "fabric": {
    "psk": "${fabric_psk}",
    "link_prefix_v4": "10.240.0.0/16",
    "link_prefix_v6": "fd77::/48",
    "loopback_prefix_v6": "fd78:1234:5678::/48",
    "routing_table_id": 20000
  },
  "node": {
    "uid": {"name": "b", "uuid": "10000000-0000-4000-8000-000000000002"},
    "private_key": "${b_private}",
    "loopback_address_v6": "fd78:1234:5678::2"
  },
  "peers": [
    {
      "name": "a",
      "public_key": "${a_public}",
      "endpoints": ["192.0.2.1:51001"],
      "listen_port": 51002,
      "interface_name": "vl-b-a"
    },
    {
      "name": "c",
      "public_key": "${c_public}",
      "endpoints": ["192.0.2.3:51004"],
      "listen_port": 51003,
      "interface_name": "vl-b-c"
    }
  ],
  "domains": {
    "production": {
      "table_id": 20001,
      "source_prefixes": ["10.100.1.0/24"],
      "routes": {
        "a": ["10.100.1.0/24"],
        "c": ["192.168.20.0/24"]
      }
    }
  }
}
EOF

cat >"${runtime}/c.json" <<EOF
{
  "api_version": "velvet.io/v1alpha1",
  "kind": "NodeSpec",
  "fabric": {
    "psk": "${fabric_psk}",
    "link_prefix_v4": "10.240.0.0/16",
    "link_prefix_v6": "fd77::/48",
    "loopback_prefix_v6": "fd78:1234:5678::/48",
    "routing_table_id": 20000,
    "routes": {"b": ["fd78:1234:5678::1/128"]}
  },
  "node": {
    "uid": {"name": "c", "uuid": "10000000-0000-4000-8000-000000000003"},
    "private_key": "${c_private}",
    "loopback_address_v6": "fd78:1234:5678::3"
  },
  "peers": [{
    "name": "b",
    "public_key": "${b_public}",
    "endpoints": ["192.0.2.2:51003"],
    "listen_port": 51004,
    "interface_name": "vl-c-b"
  }],
  "domains": {
    "production": {
      "table_id": 20001,
      "source_prefixes": ["10.100.1.0/24"],
      "routes": {"b": ["10.100.1.0/24"]},
      "announcements": ["192.168.20.0/24"]
    }
  }
}
EOF

start_cluster "${runtime}/a.json" initial

for log_file in "${runtime}"/*-initial.log; do grep -q '"event":"velvet-link-established"' "${log_file}"; done
if ! ip -n "${ns_a}" -6 route show table 20000 exact fd78:1234:5678::3/128 dev vl-a-b proto 201 | grep -q fd78:1234:5678::3; then
  echo "missing A-to-C static loopback route" >&2
  ip -n "${ns_a}" -6 -details route show table 20000 >&2 || true
  exit 1
fi
if ! ip -n "${ns_b}" route show table 20001 exact 192.168.20.0/24 dev vl-b-c proto 201 | grep -q 192.168.20.0/24; then
  echo "missing B service route" >&2
  ip -n "${ns_b}" -details route show table 20001 >&2 || true
  ip -n "${ns_b}" -details route show table 20000 >&2 || true
  exit 1
fi
ip -n "${ns_b}" route show table 20001 exact 10.100.1.0/24 dev vl-b-a proto 201 | grep -q 10.100.1.0/24
ip -n "${ns_c}" route show table 20001 type throw exact 192.168.20.0/24 proto 201 | grep -q 192.168.20.0/24
ip -n "${ns_b}" -details rule show | grep -q 'from 10.100.1.0/24 lookup 20001 proto 201'
test "$(ip netns exec "${ns_b}" sh -c 'cat /proc/sys/net/ipv4/ip_forward')" = 1
test "$(ip netns exec "${ns_b}" sh -c 'cat /proc/sys/net/ipv6/conf/all/forwarding')" = 1
b_link4=$(ip -n "${ns_b}" -o -4 address show dev vl-b-a scope global | awk 'NR == 1 {print $4}' | cut -d/ -f1)
b_link6=$(ip -n "${ns_b}" -o -6 address show dev vl-b-a scope global | awk 'NR == 1 {print $4}' | cut -d/ -f1)
if test -z "${b_link4}" || test -z "${b_link6}" || \
   ! ip -n "${ns_a}" route show table 20000 dev vl-a-b proto 202 | grep -q '10.240.' || \
   ! ip -n "${ns_a}" -6 route show table 20000 dev vl-a-b proto 202 | grep -q 'fd77:'; then
  echo "numbered Link state is incomplete: peer_v4=${b_link4:-missing} peer_v6=${b_link6:-missing}" >&2
  ip -n "${ns_b}" -o address show dev vl-b-a >&2 || true
  ip -n "${ns_a}" -details route show table 20000 >&2 || true
  ip -n "${ns_a}" -6 -details route show table 20000 >&2 || true
  exit 1
fi
ip netns exec "${ns_a}" ping -c 1 -W 3 "${b_link4}" >/dev/null
ip netns exec "${ns_a}" ping -6 -c 1 -W 3 "${b_link6}" >/dev/null
ip netns exec "${ns_a}" ping -6 -c 1 -W 3 fd78:1234:5678::3 >/dev/null
for ns in "${ns_a}" "${ns_b}" "${ns_c}"; do ip -n "${ns}" rule add priority 19999 to 10.100.1.0/24 lookup 20001; done
ip netns exec "${ns_a}" ping -c 1 -W 3 -I 10.100.1.1 192.168.20.1 >/dev/null

ip -n "${ns_a}" route add blackhole 203.0.113.0/24 table 20000 proto 204
ip -n "${ns_a}" rule add priority 32000 to 203.0.113.0/24 lookup 20000 protocol 204

cat >"${runtime}/a-updated.json" <<EOF
{
  "api_version": "velvet.io/v1alpha1",
  "kind": "NodeSpec",
  "fabric": {
    "psk": "${fabric_psk}",
    "link_prefix_v4": "10.240.0.0/16",
    "link_prefix_v6": "fd77::/48",
    "loopback_prefix_v6": "fd78:1234:5678::/48",
    "routing_table_id": 21000,
    "routes": {"b": ["fd78:1234:5678::3/128"]}
  },
  "node": {
    "uid": {"name": "a", "uuid": "10000000-0000-4000-8000-000000000001"},
    "private_key": "${a_private}",
    "loopback_address_v6": "fd78:1234:5678::1"
  },
  "peers": [{
    "name": "b",
    "public_key": "${b_public}",
    "endpoints": ["192.0.2.2:51002"],
    "listen_port": 51001,
    "interface_name": "vl-a-b-new"
  }]
}
EOF

start_cluster "${runtime}/a-updated.json" updated

if ip -n "${ns_a}" link show vl-a-b >/dev/null 2>&1; then
    echo "stale interface vl-a-b still exists" >&2
    exit 1
fi
ip -n "${ns_a}" link show vl-a-b-new >/dev/null
test -z "$(ip -n "${ns_a}" -6 route show table 20000 proto 201 2>/dev/null)"
test -z "$(ip -n "${ns_a}" -6 route show table 20000 proto 202 2>/dev/null)"
test -z "$(ip -n "${ns_a}" route show table 20001 proto 201 2>/dev/null)"
test -z "$(ip -n "${ns_a}" -6 route show table 20001 proto 201 2>/dev/null)"
test -z "$(ip -n "${ns_a}" -details rule show | grep 'lookup \(20000\|20001\) proto 201' || true)"
test -z "$(ip -n "${ns_a}" -6 -details rule show | grep 'lookup \(20000\|20001\) proto 201' || true)"
ip -n "${ns_a}" route show table 20000 exact 203.0.113.0/24 proto 204 | grep -q 203.0.113.0/24
ip -n "${ns_a}" -details rule show | grep -q 'to 203.0.113.0/24 lookup 20000 proto 204'
ip -n "${ns_a}" -6 route show table 21000 exact fd78:1234:5678::3/128 dev vl-a-b-new proto 201 | grep -q fd78:1234:5678::3
ip -n "${ns_a}" link show access0 >/dev/null

echo "velvet three-node Core routing and ownership CRUD E2E: PASS"

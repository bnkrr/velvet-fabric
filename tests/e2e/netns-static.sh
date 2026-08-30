#!/bin/sh
set -eu

velvetd=${1:?usage: netns-static.sh /path/to/velvetd}
test -x "${velvetd}" || { echo "velvetd is not executable: ${velvetd}" >&2; exit 2; }
test "$(id -u)" -eq 0 || { echo "netns E2E must run as root" >&2; exit 2; }
for command in ip wg ping awk grep mktemp tr wc cut kill; do command -v "${command}" >/dev/null || { echo "missing command: ${command}" >&2; exit 2; }; done

suffix=$$
ns_a="vl-a-${suffix}"
ns_b="vl-b-${suffix}"
runtime=$(mktemp -d /tmp/velvet-e2e.XXXXXXXX)
pid_a=
pid_b=
cleanup() {
	status=$?
	if test "${status}" -ne 0; then
		test ! -f "${runtime}/a.log" || cat "${runtime}/a.log" >&2
		test ! -f "${runtime}/b.log" || cat "${runtime}/b.log" >&2
		ip -n "${ns_a}" -details link show 2>/dev/null >&2 || true
		ip -n "${ns_b}" -details link show 2>/dev/null >&2 || true
		ip -n "${ns_a}" -6 -details route show table all 2>/dev/null >&2 || true
		ip -n "${ns_b}" -6 -details route show table all 2>/dev/null >&2 || true
		ip -n "${ns_a}" -6 -details rule show 2>/dev/null >&2 || true
		ip -n "${ns_b}" -6 -details rule show 2>/dev/null >&2 || true
	fi
  test -z "${pid_a}" || kill "${pid_a}" 2>/dev/null || true
  test -z "${pid_b}" || kill "${pid_b}" 2>/dev/null || true
  ip netns del "${ns_a}" 2>/dev/null || true
  ip netns del "${ns_b}" 2>/dev/null || true
  rm -rf -- "${runtime}"
}
trap cleanup EXIT INT TERM

umask 077
wg genkey > "${runtime}/a.key"
wg genkey > "${runtime}/b.key"
wg pubkey < "${runtime}/a.key" > "${runtime}/a.pub"
wg pubkey < "${runtime}/b.key" > "${runtime}/b.pub"
wg genpsk > "${runtime}/fabric.psk"
a_private=$(tr -d '\n' < "${runtime}/a.key")
b_private=$(tr -d '\n' < "${runtime}/b.key")
a_public=$(tr -d '\n' < "${runtime}/a.pub")
b_public=$(tr -d '\n' < "${runtime}/b.pub")
fabric_psk=$(tr -d '\n' < "${runtime}/fabric.psk")

ip netns add "${ns_a}"
ip netns add "${ns_b}"
ip link add "ua-${suffix}" type veth peer name "ub-${suffix}"
ip link set "ua-${suffix}" netns "${ns_a}"
ip link set "ub-${suffix}" netns "${ns_b}"
ip -n "${ns_a}" link set lo up
ip -n "${ns_b}" link set lo up
ip -n "${ns_a}" addr add 192.0.2.1/24 dev "ua-${suffix}"
ip -n "${ns_b}" addr add 192.0.2.2/24 dev "ub-${suffix}"
ip -n "${ns_a}" link set "ua-${suffix}" up
ip -n "${ns_b}" link set "ub-${suffix}" up

# A NodeSpec without Babel must remove state left by a previously managed
# protocol-203 daemon, while preserving differently owned kernel state.
ip -n "${ns_a}" -6 route add blackhole 2001:db8:dead::/48 table 20000 proto 203
ip -n "${ns_a}" -6 rule add priority 32003 to 2001:db8:dead::/48 lookup 20000 protocol 203

cat > "${runtime}/a.json" <<EOF
{
  "api_version": "velvet.io/v1alpha1",
  "kind": "NodeSpec",
  "fabric": {
    "psk": "${fabric_psk}",
    "loopback_prefix_v6": "fd78:1234:5678::/48"
  },
  "node": {"uid": {"name": "a"}, "private_key": "${a_private}"},
  "peers": [{
    "name": "b",
    "public_key": "${b_public}",
    "endpoints": ["192.0.2.2:51002"],
    "listen_port": 51001,
    "persistent_keepalive_seconds": 5
  }]
}
EOF

cat > "${runtime}/b.json" <<EOF
{
  "api_version": "velvet.io/v1alpha1",
  "kind": "NodeSpec",
  "fabric": {
    "psk": "${fabric_psk}",
    "loopback_prefix_v6": "fd78:1234:5678::/48"
  },
  "node": {"uid": {"name": "b"}, "private_key": "${b_private}"},
  "peers": [{
    "name": "a",
    "public_key": "${a_public}",
    "endpoints": ["192.0.2.1:51001"],
    "listen_port": 51002,
    "interface_name": "vl-b-custom"
  }]
}
EOF

ip netns exec "${ns_a}" "${velvetd}" --config "${runtime}/a.json" --once >"${runtime}/a.log" 2>&1 &
pid_a=$!
ip netns exec "${ns_b}" "${velvetd}" --config "${runtime}/b.json" --once >"${runtime}/b.log" 2>&1 &
pid_b=$!

attempt=0
while kill -0 "${pid_a}" 2>/dev/null || kill -0 "${pid_b}" 2>/dev/null; do
  attempt=$((attempt + 1))
  if test "${attempt}" -ge 30; then
    echo "velvetd did not establish the Link" >&2
    cat "${runtime}/a.log" >&2
    cat "${runtime}/b.log" >&2
    ip -n "${ns_a}" address show >&2
    ip -n "${ns_b}" address show >&2
    ip netns exec "${ns_a}" wg show >&2
    ip netns exec "${ns_b}" wg show >&2
    exit 1
  fi
  sleep 1
done
wait "${pid_a}"
wait "${pid_b}"
pid_a=
pid_b=

grep -q '"uuid": "[0-9a-f-][0-9a-f-]*"' "${runtime}/a.json"
grep -q '"uuid": "[0-9a-f-][0-9a-f-]*"' "${runtime}/b.json"
grep -q '"event":"velvet-link-established"' "${runtime}/a.log"
grep -q '"event":"velvet-link-established"' "${runtime}/b.log"
test -z "$(ip -n "${ns_a}" -6 route show table 20000 proto 203)"
test -z "$(ip -n "${ns_a}" -6 -details rule show | grep 'proto 203' || true)"

test "$(ip netns exec "${ns_a}" wg show vl-a-b peers | wc -l)" -eq 1
test "$(ip netns exec "${ns_b}" wg show vl-b-custom peers | wc -l)" -eq 1
a_link_psk=$(ip netns exec "${ns_a}" wg show vl-a-b preshared-keys | awk '{print $2}')
b_link_psk=$(ip netns exec "${ns_b}" wg show vl-b-custom preshared-keys | awk '{print $2}')
test -n "${a_link_psk}" && test "${a_link_psk}" = "${b_link_psk}" && test "${a_link_psk}" != "${fabric_psk}"

a_control6=$(ip -n "${ns_a}" -o -6 addr show dev vl-a-b scope link | awk '$4 ~ /^fe80:/ {print $4}' | cut -d/ -f1)
b_control6=$(ip -n "${ns_b}" -o -6 addr show dev vl-b-custom scope link | awk '$4 ~ /^fe80:/ {print $4}' | cut -d/ -f1)
test -n "${a_control6}" && test -n "${b_control6}"
test "${a_control6}" != "${b_control6}"
a_loop6=$(ip -n "${ns_a}" -o -6 addr show dev vv-loop scope global | awk '{print $4}' | cut -d/ -f1)
b_loop6=$(ip -n "${ns_b}" -o -6 addr show dev vv-loop scope global | awk '{print $4}' | cut -d/ -f1)
test -n "${a_loop6}" && test -n "${b_loop6}"
test "$(ip -n "${ns_a}" -o -4 addr show dev vl-a-b | wc -l)" -eq 0
test "$(ip -n "${ns_b}" -o -4 addr show dev vl-b-custom | wc -l)" -eq 0
test "$(ip -n "${ns_a}" -o -6 addr show dev vl-a-b scope global | wc -l)" -eq 0
test "$(ip -n "${ns_b}" -o -6 addr show dev vl-b-custom scope global | wc -l)" -eq 0
ip -n "${ns_a}" -6 route show table 20000 exact "${b_loop6}/128" dev vl-a-b proto 202 | grep -q "${b_loop6}"
ip -n "${ns_b}" -6 route show table 20000 exact "${a_loop6}/128" dev vl-b-custom proto 202 | grep -q "${a_loop6}"
test -z "$(ip -n "${ns_a}" -6 route show table main exact "${b_loop6}/128")"
test -z "$(ip -n "${ns_b}" -6 route show table main exact "${a_loop6}/128")"
ip -n "${ns_a}" -6 route show table 20000 exact fd78:1234:5678::/48 type unreachable proto 201 | grep -q fd78:1234:5678::/48
ip -n "${ns_b}" -6 route show table 20000 exact fd78:1234:5678::/48 type unreachable proto 201 | grep -q fd78:1234:5678::/48
ip -n "${ns_a}" -6 -details rule show | grep -q 'to fd78:1234:5678::/48 lookup 20000 proto 201'
ip -n "${ns_b}" -6 -details rule show | grep -q 'to fd78:1234:5678::/48 lookup 20000 proto 201'
ip netns exec "${ns_a}" ping -6 -c 1 -W 2 "${b_loop6}" >/dev/null
ip netns exec "${ns_b}" ping -6 -c 1 -W 2 "${a_loop6}" >/dev/null
test "$(ip netns exec "${ns_a}" wg show vl-a-b dump | awk 'NR == 2 {print $8}')" = "5"

echo "velvet VFP unnumbered static-Link E2E: PASS"

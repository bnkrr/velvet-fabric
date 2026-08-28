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

test "$(ip netns exec "${ns_a}" wg show vl-a-b peers | wc -l)" -eq 1
test "$(ip netns exec "${ns_b}" wg show vl-b-custom peers | wc -l)" -eq 1
a_link_psk=$(ip netns exec "${ns_a}" wg show vl-a-b preshared-keys | awk '{print $2}')
b_link_psk=$(ip netns exec "${ns_b}" wg show vl-b-custom preshared-keys | awk '{print $2}')
test -n "${a_link_psk}" && test "${a_link_psk}" = "${b_link_psk}" && test "${a_link_psk}" != "${fabric_psk}"

test "$(ip -n "${ns_a}" -o -6 addr show dev vl-a-b scope link | awk '$4 ~ /^fe80::[12]\/64$/ {print $4}' | wc -l)" -eq 1
test "$(ip -n "${ns_b}" -o -6 addr show dev vl-b-custom scope link | awk '$4 ~ /^fe80::[12]\/64$/ {print $4}' | wc -l)" -eq 1
a_loop6=$(ip -n "${ns_a}" -o -6 addr show dev vl-loop scope global | awk '{print $4}' | cut -d/ -f1)
b_loop6=$(ip -n "${ns_b}" -o -6 addr show dev vl-loop scope global | awk '{print $4}' | cut -d/ -f1)
test -n "${a_loop6}" && test -n "${b_loop6}"
test "$(ip -n "${ns_a}" -o -4 addr show dev vl-a-b | wc -l)" -eq 0
test "$(ip -n "${ns_b}" -o -4 addr show dev vl-b-custom | wc -l)" -eq 0
test "$(ip -n "${ns_a}" -o -6 addr show dev vl-a-b scope global | wc -l)" -eq 0
test "$(ip -n "${ns_b}" -o -6 addr show dev vl-b-custom scope global | wc -l)" -eq 0
ip -n "${ns_a}" -6 route show exact "${b_loop6}/128" dev vl-a-b | grep -q "${b_loop6}"
ip -n "${ns_b}" -6 route show exact "${a_loop6}/128" dev vl-b-custom | grep -q "${a_loop6}"
ip netns exec "${ns_a}" ping -6 -c 1 -W 2 "${b_loop6}" >/dev/null
ip netns exec "${ns_b}" ping -6 -c 1 -W 2 "${a_loop6}" >/dev/null
test "$(ip netns exec "${ns_a}" wg show vl-a-b dump | awk 'NR == 2 {print $8}')" = "5"

echo "velvet VFP unnumbered static-Link E2E: PASS"

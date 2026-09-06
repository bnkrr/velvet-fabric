# Shared physical fixture for the eight-node Core scenarios. Callers provide
# runtime, nodes, bridge, suffix and namespace(); routing expectations stay local.
create_core_keys() (
  umask 077
  wg genpsk >"${runtime}/fabric.psk"
  for node in ${nodes}; do
    wg genkey >"${runtime}/${node}.key"
    wg pubkey <"${runtime}/${node}.key" >"${runtime}/${node}.pub"
  done
)

create_core_underlay() (
  prefix=$1
  ip link add "${bridge}" type bridge
  ip link set "${bridge}" up
  index=0
  for item in \
    "ea:192.0.2.11" "eb:192.0.2.12" \
    "r1:192.0.2.21" "r2:192.0.2.22" "r3:192.0.2.23" \
    "xa:192.0.2.31" "xb:192.0.2.32" "xc:192.0.2.33"; do
    node=${item%%:*}; address=${item#*:}; ns=$(namespace "${node}")
    index=$((index + 1)); root_if="${prefix}r${index}-${suffix}"; node_if="${prefix}n${index}-${suffix}"
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
)

add_attached() (
  node=$1; interface=$2; shift 2; ns=$(namespace "${node}")
  ip -n "${ns}" link add "${interface}" type dummy
  for address in "$@"; do ip -n "${ns}" address add "${address}" dev "${interface}"; done
  ip -n "${ns}" link set "${interface}" up
)

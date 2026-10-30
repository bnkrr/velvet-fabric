# Three-node Access and exit examples

Both examples use the same topology and IPv4 Access pool:

```text
client 10.100.20.2
        |
A (10.100.20.1) --- B --- C --- upstream / Internet
192.0.2.1       192.0.2.2  192.0.2.3
```

| Example | Routes |
| --- | --- |
| [static_minimal](static_minimal/) | Explicit next-hop routes; no Babel |
| [dynamic_minimal](dynamic_minimal/) | Babel learns next hops from announcements |

Each directory contains the actual `a.json`, `b.json` and `c.json` templates.
The dynamic example enables dynamic **routing**, not Dynamic Links: both retain
the A–B–C path, with no A–C WireGuard peer. IPv6 node loopbacks are used for
Fabric infrastructure; these minimal examples provide IPv4 client access.

All three nodes configure Domain `internet`, table `20001`, and the complete
source set `10.100.20.0/24`. A announces that pool in `domains.internet.announcements`;
C announces `0.0.0.0/0` in `domains.internet.announcements`. B has no local
announcements. Velvet generates `from 10.100.20.0/24 lookup 20001` and
`to 10.100.20.0/24 lookup 20000` on every node. Unmatched host traffic keeps its
existing routing policy.

## Prepare and start

From the repository root, with Python 3 and `wg` installed:

```sh
python3 examples/prepare.py static_minimal .local/examples/static_minimal
python3 examples/prepare.py dynamic_minimal .local/examples/dynamic_minimal \
  --babel /usr/local/bin/babel-rs
```

Choose one example. Preparation creates fresh keys, a shared Fabric PSK and
unique node UUIDs; it preserves the templates' routes and announcements. It
writes mode-0600 files and refuses to overwrite an existing output directory.
Keep and reuse those generated configs for restarts.

Replace the documentation underlay addresses in `peers[].endpoints` with your
actual reachable node addresses. Preserve the per-Link UDP port pairs:
A `51001` ↔ B `51002`, B `51003` ↔ C `51004`. All nodes need kernel WireGuard;
the dynamic example also needs the compatible `babel-rs` binary documented in
the main README. Underlay routing must work before starting Velvet.

Copy each generated file to its corresponding node as `/etc/velvet/node.json`,
preserving mode `0600`. On each node:

```sh
sudo velvetctl resolve --config /etc/velvet/node.json
sudo velvetd --config /etc/velvet/node.json
```

## Local Access and exit delivery

The configs manage Fabric, not WG/IKEv2 Access services or Internet NAT.
On A, the Access service must deliver `10.100.20.0/24` locally and give clients
a route/default route through A. For a host-originated demonstration without
an Access service, create a dummy interface on A:

```sh
sudo ip link add access0 type dummy
sudo ip address add 10.100.20.1/24 dev access0
sudo ip link set access0 up
```

On C, provide a working upstream route in the host's main table. For the
isolated lab used by the test, `uplink0` has `198.51.100.1/30` and the gateway is
`198.51.100.2`:

```sh
sudo ip route add default via 198.51.100.2 dev uplink0
```

If the upstream has no return route to the Access pool, configure NAT on C
(substitute your real upstream interface for `uplink0`):

```sh
sudo nft -f - <<'EOF'
table ip velvet_example_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 10.100.20.0/24 oifname "uplink0" masquerade
  }
}
EOF
```

Allow forwarding between Access, Fabric and the upstream in your host firewall.
Velvet enables IP forwarding on the routing nodes, but does not manage firewall
or NAT policy. On C the Domain's local default announcement produces a `throw`
route, allowing the host's main-table default to deliver outbound traffic.

In the test lab, the upstream hosts `203.0.113.10`. From A:

```sh
ping -I 10.100.20.1 203.0.113.10
ping -6 fd78:abcd::3
```

Use a destination actually reachable through C outside the test lab. The first
ping explicitly uses an Access source; an ordinary host ping is not expected to
select the Domain. Real clients use their own assigned Access addresses.

## Verification

The regression uses these templates directly, substitutes only keys/UUIDs and
the Babel executable path, and creates a real client namespace behind A plus
an upstream namespace behind C. It checks the A–B–C next hops, client ping
through C's NAT, return traffic, node loopbacks and static versus Babel route
ownership. It does not install external return-selection rules.

On a disposable root Linux test host with the network tools installed:

```sh
sudo python3 tests/e2e/netns-examples.py \
  /absolute/path/to/velvetd /absolute/path/to/babel-rs /absolute/path/to/velvetctl
```

Or configure the [VM runner](../tests/VM.md) and run:

```sh
tests/e2e/run-on-vm.sh examples
```

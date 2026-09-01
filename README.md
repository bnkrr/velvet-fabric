# Velvet Fabric

## Purpose

Velvet Fabric builds and maintains a routed network core from preconfigured
point-to-point WireGuard adjacencies. Each node runs one `velvetd`, described by
a local NodeSpec. The daemon creates a dedicated WireGuard interface for every
configured Peer, gives the node a stable IPv6 loopback, and reconciles the
interfaces, routes, and policy rules owned by that NodeSpec.

Velvet supports both local static routing and optional distributed dynamic
routing. For dynamic routing, `velvetd` manages one independent
[`babel-rs`](https://github.com/bnkrr/babel-rs) process for all Links in the
node. Babel exchanges routes over the WireGuard interfaces; it is not carried
inside Velvet's own control protocol.

## Current scope

The current release provides:

- static WireGuard Links whose peer public keys and endpoint candidates are
  configured on both endpoints;
- link-local discovery and version-1 VFP sessions between adjacent nodes;
- deterministic node loopbacks and optional negotiated IPv4/IPv6 Link
  addresses;
- idempotent reconciliation of Velvet-owned interfaces, routes, and policy
  rules;
- static Core routes and source-selected Domain routing tables;
- optional multi-hop route discovery through a supervised `babel-rs` daemon;
- transactional reload, local status, and graceful shutdown.

It does not currently discover arbitrary peers, exchange WireGuard keys, or
create dynamic Links. Access interfaces, access tunnels, and NAT are also
outside Velvet Core. An announcement asserts that a prefix is already
delivered locally by external access configuration; it does not create that
configuration.

The daemon and its reconciler currently target Linux. There is one `velvetd`
per Linux network namespace.

## Architecture

```text
NodeSpec
   |
   v
velvetd
   |-- WireGuard Links and stable node loopback
   |-- VFP over link-local TCP: adjacent-Link control and address negotiation
   |-- static Core routes and policy rules
   `-- optional managed babel-rs
          `-- standard Babel over link-local UDP: dynamic route propagation
```

WireGuard is the data plane. VFP is Velvet's inter-node control protocol and
does not transport routes. Babel is the dynamic routing protocol and does not
create WireGuard Links. Static routes remain local desired state and are not
propagated over VFP.

The version-1 VFP specification is
[docs/protocol/VFP.md](docs/protocol/VFP.md). Informative design references are
kept under `docs/protocol/refs/`.

## Quick start

Build the daemon and local control client:

```sh
mkdir -p bin
go build -o bin/velvetd ./cmd/velvetd
go build -o bin/velvetctl ./cmd/velvetctl
```

A minimal NodeSpec for node `a` is:

```json
{
  "api_version": "velvet.io/v1alpha1",
  "kind": "NodeSpec",
  "fabric": {
    "psk": "<base64-32-byte-fabric-psk>",
    "loopback_prefix_v6": "fd78:1234:5678::/48"
  },
  "node": {
    "uid": {"name": "a"},
    "private_key": "<inline-node-a-wireguard-private-key>"
  },
  "peers": [
    {
      "name": "b",
      "public_key": "<node-b-wireguard-public-key>",
      "endpoints": ["192.0.2.2:51002"],
      "listen_port": 51001
    }
  ]
}
```

Node `b` uses the same Fabric PSK and loopback prefix, its own private key,
node `a`'s public key, local listen port `51002`, and an endpoint for node `a`
on port `51001`. Peer names are local readable aliases; the remote persistent
UUID is learned through VFP and is never configured.

Inspect all non-secret derived values before starting:

```sh
bin/velvetctl resolve --config node.json
```

If `node.uid.uuid` is absent, this first load generates a UUIDv4 and atomically
writes it back to the same JSON file. Start the daemon and query its status:

```sh
sudo bin/velvetd --config node.json
sudo bin/velvetctl status --config node.json
```

This minimal configuration establishes one adjacent Link. It does not provide
multi-hop routing until static routes are configured or Babel is enabled.

## Link configuration

Keys are embedded directly in NodeSpec. `fabric.psk` must be a base64-encoded
32-byte key and is shared by every node in the Fabric. Each node has one local
WireGuard private key, while every Peer entry contains the corresponding remote
public key and at least one endpoint candidate.

Four peer fields are optional:

```json
{
  "listen_port": 51001,
  "link_addresses": ["10.77.0.0/30", "fd77::/126"],
  "persistent_keepalive_seconds": 25,
  "interface_name": "vl-a-b"
}
```

Velvet derives one node-owned IPv6 `/128` on `vv-loop` from
`fabric.loopback_prefix_v6`. For every Link it also derives a stable local IPv6
link-local control address from the node UUID, effective interface name, and
Fabric PSK. It assigns that address to the dedicated WireGuard interface,
discovers the actual remote address using link-local UDP multicast, and runs
VFP over TCP port 58420. The lower discovered IPv6 address initiates TCP;
neither endpoint configures or predicts the remote control address.

`fabric.link_prefix_v4` and `fabric.link_prefix_v6` are independent optional
infrastructure pools. Configuring one makes Velvet propose a `/30` or `/126`
for that family; configuring both produces a dual-stack numbered Link. With no
Link pools, peers accept an empty proposal and the Link remains unnumbered
apart from its control address. Velvet control traffic and routed traffic do
not require numbered Link addresses.

`link_addresses` contains Link network prefixes, not endpoint host addresses.
The lower Node UUID receives the first host and the higher UUID the second. An
explicit `/30` or `/126` requires the corresponding Fabric Link pool, must be
inside it, and replaces only that address family's derived prefix.

Velvet also derives the local interface name, listen port, node loopback, and
the actual WireGuard per-Link PSK. Explicit optional values replace only their
matching defaults. `fabric.vfp_port` and `node.loopback_address_v6` are optional
overrides. Endpoint candidates are tried in order; a candidate without a fresh
WireGuard handshake is rotated after a bounded interval, while a successful
handshake retains the working endpoint.

An omitted field that Velvet defines as derived still contributes its derived
value to desired state. A setting left to the kernel, such as an omitted route
metric or persistent keepalive, is neither written nor compared. Omitted route
collections are treated as empty Velvet-owned desired state, but omission does
not grant ownership of unrelated kernel objects.

## Core routing

The Fabric routing table carries node and infrastructure reachability.
`fabric.routing_table_id` defaults to `20000`. Static Fabric routes are grouped
by their locally named next-hop Peer:

```json
{
  "fabric": {
    "routes": {
      "b": [
        "fd78:1234:5678::3/128",
        {"prefix": "fd78:1234:5678::4/128", "metric": 10}
      ]
    }
  }
}
```

A Domain is a source-selected routing view. Every Domain has its own table and
every configured source prefix installs a `from` rule selecting that table.
This allows different source populations to use different exits while sharing
the same Fabric topology:

```json
{
  "domains": {
    "production": {
      "table_id": 20001,
      "source_prefixes": ["10.100.1.0/24"],
      "routes": {"b": ["192.168.20.0/24"]},
      "announcements": ["0.0.0.0/0"]
    }
  }
}
```

An announcement declares that the local node can deliver the prefix outside
Velvet Core. Velvet installs a `throw` route in the managed view so lookup can
continue to the external delivery route. Without Babel, announcements remain
local and are not propagated. With Babel enabled, Fabric announcements become
ordinary Babel origins and Domain announcements become RFC 9079
source-specific origins.

For each address family, the first source prefix in a Domain is its canonical
RFC 9079 source. Additional source prefixes are aliases selecting the same
Linux route view.

## Dynamic routing

The `babel` section is optional. When present, `enabled` is required and
`executable` may select an absolute `babel-rs` path:

```json
{
  "babel": {
    "enabled": true,
    "executable": "/usr/local/bin/babel-rs"
  }
}
```

When enabled, `velvetd` generates and validates a strict `babel-rs`
configuration, starts one process for all local WireGuard Links, and
automatically originates the node loopback. It reloads the child online as
Link origins change and restarts an unexpected exit with bounded exponential
backoff. Parent death terminates the child.

`babel-rs` uses UDP/6696 and `ff02::1:6` on every managed WireGuard interface.
It owns dynamic routes with protocol `203`; `velvetd` owns static routes and
rules with protocol `201` and adjacent routes with protocol `202`. Static and
dynamic routes share tables, with dynamic priorities placed after the complete
static metric range. Neither daemon writes learned routes to `main`.

## Operations

There is one `velvetd` and one optional managed `babel-rs` process per network
namespace. A per-namespace lock rejects a second `velvetd`. Read status or
request a transactional reload or graceful shutdown through the local control
socket:

```sh
sudo velvetctl status --config node.json
sudo velvetctl reload --config node.json
sudo velvetctl shutdown --config node.json
```

The per-node Unix socket is mode `0600` below `/run/velvet/<uuid>/`. SIGHUP also
loads and validates a complete NodeSpec candidate. An invalid candidate leaves
the active generation running; if starting a valid replacement fails,
`velvetd` starts the previous generation again.

[`packaging/systemd/velvetd.service`](packaging/systemd/velvetd.service) is a
deployment template with restart-on-failure, runtime and state directories,
and a minimal capability set. Install `babel-rs` at the configured path when
dynamic routing is enabled; do not separately enable its standalone service
for a Velvet-managed instance.

## Development and testing

Run local tests:

```sh
go test ./...
```

The privileged Linux E2E suite under `tests/e2e/` creates disposable network
namespaces. It covers adjacent unnumbered Links, static Core reconciliation and
CRUD, and an eight-node, eight-Link, two-Domain topology. The dynamic test uses
no static multi-hop routes: Babel discovers the paths, all node loopbacks are
checked, Domain forwarding is exercised, and child withdrawal and restart
convergence are verified. The same suite runs in GitHub Actions.

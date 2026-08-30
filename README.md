# Velvet Fabric

This repository implements static point-to-point WireGuard Links and both
static and Babel-driven Core routing. `velvetd` reconciles interfaces, routes,
and policy rules from NodeSpec and can manage the independent `babel-rs`
daemon. Access interfaces and NAT remain outside Velvet Core.

The version-1 inter-node control protocol is specified in
[docs/protocol/VFP.md](docs/protocol/VFP.md). Informative design references are
kept beside the specification under `docs/protocol/refs/`.

## NodeSpec

Keys are embedded directly. The required functional fields are the Fabric PSK,
an IPv6 loopback prefix, the local private key, and each locally named peer's
public key and endpoint candidates. The local UID name is an optional readable
prefix. Its UUID may be omitted on first start; Velvet generates it and
atomically writes it back to the same JSON file. A remote UUID is learned
through VFP `OPEN` and is never configured.

```json
{
  "api_version": "velvet.io/v1alpha1",
  "kind": "NodeSpec",
  "fabric": {
    "psk": "<inline-fabric-psk>",
    "loopback_prefix_v6": "fd78:1234:5678::/48"
  },
  "node": {
    "uid": {"name": "a"},
    "private_key": "<inline-node-private-key>"
  },
  "peers": [
    {
      "name": "b",
      "public_key": "<inline-peer-public-key>",
      "endpoints": ["192.0.2.2:51002"]
    }
  ]
}
```

Exactly four groups of optional Link settings are accepted on a peer:

```json
{
  "listen_port": 51001,
  "link_addresses": ["10.77.0.0/30", "fd77::/126"],
  "persistent_keepalive_seconds": 25,
  "interface_name": "vl-a-b"
}
```

Velvet derives one node-owned IPv6 `/128` on `vv-loop` from the required loopback pool and
one stable local IPv6 link-local control address per Link from the node UUID,
local interface identity, and Fabric PSK. It assigns that scoped address to
each dedicated WireGuard interface,
discovers the remote address using link-local UDP multicast, and then runs VFP
over TCP port 58420. The lower of the two discovered IPv6 addresses initiates
TCP; neither endpoint configures or predicts the remote address. With no Link
pools configured, the peers accept an empty proposal and the Link remains
unnumbered apart from its control address.

`fabric.link_prefix_v4` and `fabric.link_prefix_v6` are independent optional
infrastructure pools. Configuring either one makes Velvet propose a `/30` or
`/126` for that address family. Configuring both produces a dual-stack numbered
Link. These addresses are optional diagnostics and compatibility resources;
Velvet control traffic and routed traffic do not require them.

`link_addresses` contains Link network prefixes, not endpoint host addresses.
The lower Node UUID receives the first host and the higher UUID the second. An
explicit `/30` or `/126` requires the corresponding optional Fabric Link pool,
must remain inside it, and replaces only that address family's derived prefix.

Velvet also derives the local interface name, listen port, node loopback, and
the actual WireGuard per-Link PSK. Explicit optional values replace only their
matching defaults. `fabric.vfp_port` and `node.loopback_address_v6` are optional
overrides. Multiple endpoint candidates are tried in order. A candidate with
no fresh WireGuard handshake is rotated after a bounded attempt interval;
successful handshakes keep the working endpoint.

An omitted field that Velvet defines as derived still contributes that derived
value to desired state. A parameter left to the kernel, such as an omitted
route metric or persistent keepalive, is neither written nor compared. Omitted
`fabric.routes`, Domain routes, or `domains` means the corresponding
Velvet-owned collection is empty,
so stale owned entries are removed. Omission does not grant Velvet ownership of
unrelated kernel state.

## Core routing

`fabric.routing_table_id` is optional and defaults to `20000`. Static
`fabric.routes` are installed in that Fabric table and grouped by the locally named
next-hop Peer:

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

Each Domain has its own table. Every source prefix installs a `from` rule for
that table. Static routes are grouped by next-hop Peer; announcements declare
prefixes delivered locally and are projected as Linux `throw` routes before
being originated when Babel is enabled:

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

Static routing remains local desired state and is not propagated over VFP.
With `babel.enabled=true`, `velvetd` generates a strict `babel-rs` config,
starts and supervises the daemon, and automatically originates the local Node
loopback. Fabric announcements are ordinary Babel routes. For each address
family, the first source prefix in a Domain is its canonical RFC 9079 source;
the remaining source prefixes are aliases selecting the same Linux route view.

`babel-rs` uses UDP/6696 and `ff02::1:6` on every configured WG interface. It
owns dynamic routes with protocol `203`; `velvetd` owns static routes/rules
with protocol `201` and adjacent routes with protocol `202`. Static and
dynamic routes share tables, with dynamic metrics placed after the complete
static metric range. Neither daemon writes learned routes to `main`.

There is one `velvetd` per Linux network namespace and one managed `babel-rs`
process for all of that node's WireGuard Links. A per-netns lock rejects a
second daemon. `velvetd` preflights generated Babel configuration, waits for
the versioned control socket to become ready, verifies the active config
digest, reloads it online as Link origins change, and restarts an unexpected
exit with bounded exponential backoff. Parent death terminates the child.

SIGHUP loads and validates a complete NodeSpec candidate. An invalid candidate
leaves the active generation running. A valid candidate is committed as one
runtime generation; failure starts the previous generation again. SIGINT,
SIGTERM, or `velvetctl shutdown` use graceful child shutdown before signal and
kill fallbacks.

The `babel` section is optional. When present, `enabled` is required and
`executable` may set an absolute path:

```json
{"babel": {"enabled": true, "executable": "/usr/local/bin/babel-rs"}}
```

Use `velvetctl resolve` to inspect non-secret derived state:

```sh
go run ./cmd/velvetctl resolve --config node.json
```

The same tool queries the local daemon or requests a transactional reload or
shutdown. Its per-node Unix socket is mode `0600` below `/run/velvet/<uuid>/`:

```sh
velvetctl status --config node.json
velvetctl reload --config node.json
velvetctl shutdown --config node.json
```

[`packaging/systemd/velvetd.service`](packaging/systemd/velvetd.service) is a
deployment template with restart-on-failure, runtime/state directories, and a
minimal capability set. Install the local `babel-rs` binary at the absolute
path configured in NodeSpec; do not also enable its standalone service for a
Velvet-managed instance.

## Tests

Run local tests:

```sh
go test ./...
```

The Linux E2E suite runs in isolated network namespaces on `debsrv`. It covers
adjacent unnumbered Links, static Core routing/CRUD, and an eight-node,
eight-Link, two-Domain Core topology reproduced from wg-admin's complex test.
The dynamic milestone has no static multi-hop routes: Babel discovers every
path, all 64 Node-loopback pairs are checked, Domain forwarding is exercised,
and managed-daemon withdrawal/restart convergence is verified.

```sh
tests/e2e/run-on-debsrv.sh dynamic
```

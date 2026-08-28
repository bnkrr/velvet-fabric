# Velvet Fabric

This repository implements static point-to-point WireGuard Links plus the Core
static-routing stage. Velvet reconciles its owned interfaces, routes, and policy
rules from the current kernel state to the NodeSpec. Access interfaces, NAT, and
Announcements are outside this repository's current scope.

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

Velvet derives one node-owned IPv6 `/128` from the required loopback pool and
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
overrides. Multiple endpoint candidates are accepted; the current minimal
kernel backend applies the first candidate.

An omitted field that Velvet defines as derived still contributes that derived
value to desired state. A parameter left to the kernel, such as an omitted
route metric or persistent keepalive, is neither written nor compared. Omitted
`routes` or `domains` means the corresponding Velvet-owned collection is empty,
so stale owned entries are removed. Omission does not grant Velvet ownership of
unrelated kernel state.

## Static Core routing

`fabric.routing_table_id` is optional and defaults to `20000`. Top-level
`routes` are installed in that Fabric table and grouped by the locally named
next-hop Peer:

```json
{
  "routes": {
    "b": [
      "fd78:1234:5678::3/128",
      {"prefix": "fd78:1234:5678::4/128", "metric": 10}
    ]
  }
}
```

Each Domain has its own table. Its source prefixes select the table in both
directions, its routes are again grouped by next-hop Peer, and its exceptions
are Linux `throw` routes that continue lookup through later policy rules:

```json
{
  "domains": {
    "production": {
      "table_id": 20001,
      "source_prefixes": ["10.100.1.0/24"],
      "routes": {"b": ["192.168.20.0/24"]},
      "exceptions": ["10.100.1.0/24"]
    }
  }
}
```

Static routing is local desired state and is not propagated over VFP. Velvet
does not write these routes to `main`. It marks owned interfaces with a link
alias, static routes and rules with protocol `201`, and adjacent-node routes
with protocol `202`. Reconciliation replaces changed owned state and removes
stale owned state while leaving Access and differently owned kernel state
untouched. A routing table selected by the current NodeSpec must not already
contain foreign routes or rules; Velvet fails safely instead of adopting or
overwriting them.

Use `velvetctl resolve` to inspect non-secret derived state:

```sh
go run ./cmd/velvetctl resolve --config node.json
```

## Tests

Run local tests:

```sh
go test ./...
```

The Linux E2E suite runs in isolated network namespaces on `debsrv`. It covers
adjacent unnumbered Links, three-node Core routing/CRUD, and an eight-node,
eight-Link, two-Plan Core topology reproduced from wg-admin's complex real
deployment test. Access and translated NAT resources in the latter are modeled
as external attached networks; Velvet manages only the Core paths.

```sh
tests/e2e/run-on-debsrv.sh
```

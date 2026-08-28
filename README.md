# Velvet Fabric

This repository currently implements only the minimum static point-to-point
WireGuard Link agreed for the first milestone. It contains no Domain, Route, or
Announcement model.

The version-1 inter-node control protocol is specified in
[docs/protocol/VFP.md](docs/protocol/VFP.md). Informative design references are
kept beside the specification under `docs/protocol/refs/`.

## NodeSpec

Keys are embedded directly. The required functional fields are the Fabric PSK,
an IPv6 loopback prefix, the local Node UID name and private key, and each
locally named peer's public key and endpoint candidates. The local UUID may be
omitted on first start; Velvet generates it and atomically writes it back to
the same JSON file. A remote UUID is learned through VFP `OPEN` and is never
configured.

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

Velvet derives one node-owned IPv6 `/128` from the required loopback pool. It
creates each WireGuard interface with only a scoped fixed IPv6 link-local
bootstrap address, runs VFP over TCP port 58420, and exchanges Node UIDs and
IPv6 loopbacks. With no Link pools configured, the peers accept an empty
proposal and the Link remains unnumbered.

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

Use `velvetctl resolve` to inspect non-secret derived state:

```sh
go run ./cmd/velvetctl resolve --config node.json
```

## Tests

Run local tests:

```sh
go test ./...
```

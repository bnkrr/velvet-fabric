# Velvet Fabric

## Purpose

Velvet Fabric builds and maintains a routed network core from an initial set of
point-to-point WireGuard adjacencies. Each node runs one `velvetd`, described by
a local NodeSpec. The daemon creates a dedicated WireGuard interface for every
configured Peer, gives the node a stable IPv6 loopback, reconciles its network
state, and can add runtime Dynamic Links between already routed nodes.

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
- optional distributed Dynamic-Link creation using routed VFP and endpoint
  observations from existing Links;
- transactional reload, local status, and graceful shutdown.

Dynamic Link uses a bounded evidence-driven candidate search, authenticated
UDP probes, active observations and same-port WireGuard handoff. Unsupported
NAT behavior or exhausted budgets retain the existing multi-hop path.
Access interfaces, access tunnels, and NAT are outside Velvet Core. An
announcement asserts that a prefix is already delivered locally by external
access configuration; it does not create that configuration.

The daemon and its reconciler currently target Linux. There is one `velvetd`
per Linux network namespace.

## Architecture

```text
NodeSpec
   |
   v
velvetd
   |-- WireGuard Links and stable node loopback
   |-- VFP over link-local TCP: Link negotiation, closed after establishment
   |-- VFP over link-local UDP: discovery, liveness and endpoint observations
   |-- VFP over routed loopbacks: node discovery and Dynamic-Link signalling
   |-- authenticated public UDP probes: path measurements before WG handoff
   |-- static Core routes and policy rules
   `-- optional managed babel-rs
          `-- standard Babel over link-local UDP: dynamic route propagation
```

WireGuard is the data plane. VFP is Velvet's inter-node control protocol and
does not transport routes. Babel is the dynamic routing protocol and does not
create WireGuard Links. Dynamic Links reuse the normal link-bound VFP
establishment procedure for final connectivity validation. Static routes
remain local desired state and are not propagated over VFP.

Dynamic-Link admission and resource lifetime live in `internal/runtime`;
[peer.go](internal/linkdiscovery/peer.go) runs each node's evidence-driven loop.
Routed VFP coordinates candidate batches and active measurements, public UDP
finds a reciprocal path, and same-port handoff enables the normal WG/VFP
commit procedure. An exhausted task releases its tentative Link and retains
the routed path. Recovery of a committed Link remains bounded and uses that
same Link without starting a new inference task.

The version-1 VFP specification is
[docs/protocol/VFP.md](docs/protocol/VFP.md). Informative design references are
kept under `docs/protocol/refs/`.

VFP's wire format is still in internal development. TCP sessions and UDP
link-local discovery now share an eight-byte `VFP\0` header and TLV encoding,
with wire Version remaining `1`. This revision does not accept the older TCP
header or `VFPD` discovery packets; upgrade all Fabric nodes together. Link-local
discovery and liveness, and routed admission updates, remain inside the Fabric.
Public underlay probes use separate leased sockets and an authenticated,
encrypted envelope; unauthorized datagrams receive no response.

## Quick start

Linux release archives contain `velvetd` and `velvetctl` for `amd64` and `arm64`,
with SHA256 checksums on the [Releases page](https://github.com/bnkrr/velvet-fabric/releases).
For optional managed dynamic routing, install the Babel build pinned in `tests/babel-revision` separately and
set `babel.executable` to its executable path in NodeSpec.

Build the daemon and local control client:

```sh
mkdir -p bin
go build -o bin/velvetd ./cmd/velvetd
go build -o bin/velvetctl ./cmd/velvetctl
```

See [validation](tests/README.md) for test coverage and [VM setup](tests/VM.md)
for the optional privileged test runners. Maintainers follow the
[release procedure](docs/RELEASING.md), including CI and E2E acceptance of the
release tag before publication.

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
writes it back to the same JSON file. Because NodeSpec embeds the Fabric PSK
and node private key, Velvet requires a regular, non-symlink config file with
no group or other permissions (for example, mode `0600`). Start the daemon and
query its status:

```sh
sudo bin/velvetd --config node.json
sudo bin/velvetctl status --config node.json
```

This minimal configuration establishes one adjacent Link. It does not provide
multi-hop routing until static routes are configured or Babel is enabled.

For complete A–B–C configurations with an Access prefix on A and a default
exit on C, see the tested [static and dynamic examples](examples/README.md).

## Link configuration

Keys are embedded directly in NodeSpec. `fabric.psk` must be a base64-encoded
32-byte key and is shared by every node in the Fabric. Each node has one local
WireGuard private key, while every Peer entry contains the corresponding remote
public key. `endpoints` may be empty or omitted to wait for inbound WireGuard.

Additional peer fields are optional:

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

UDP ports have three explicit modes: `listen_port: 0` lets the system choose
(the default), `listen_port: 42000` fixes one port, and
`port_range: {"first": 40000, "last": 49999}` selects an inclusive range.
There is no implicit range. These fields are mutually exclusive at the same
level; `node` supplies the default for automatic Links and Peers, and an
explicit Peer choice overrides it, including an explicit zero. Fixed Peer
ports can lie outside the node range. WG, primary probes, auxiliary probes and
observers share reservations; range exhaustion never falls back outside it.
The main probe keeps its reservation during the handoff to WG. Existing ports
are preferred during a runtime; Durable records retain their actual nonzero
port across restarts. `velvetctl resolve` shows zero for ports allocated later.

Migration: older versions derived an omitted static listen port from keys.
If another node dials that port, configure its previous actual value explicitly
before upgrading, or configure a fixed listening endpoint on the other side.
An empty endpoint list never starts dynamic discovery for that Static Peer.
This Link/VFP change requires coordinated upgrades of Fabric nodes.

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

Velvet also derives the local interface name, node loopback, and
the actual WireGuard per-Link PSK. Explicit optional values replace only their
matching defaults. `fabric.vfp_port` and `node.loopback_address_v6` are optional
overrides. Endpoint candidates are tried in order; a candidate without a fresh
WireGuard handshake is rotated after a bounded interval, while a successful
handshake retains the working endpoint.

Link-bound VFP/TCP is a short negotiation: OPEN/NODE_STATE and Link-address
agreement, then close. Closing or resetting TCP does not withdraw an established
Link. Each Link sends VFP LINK_PING over its own WG interface every 10 seconds;
a fresh matching LINK_PONG confirms bidirectional reachability and can carry the
current endpoint observation. Unknown, late and duplicate replies are ignored.

After 30 seconds without confirmation, Velvet marks the control session lost
and retries. A committed Link keeps its WG interface, addresses, neighbor
loopback fallback and Babel admission. Static Links continue recovery while
configured. Ordinary Dynamic Links are removed after
`dynamic_links.recovery_timeout_seconds` without confirmation (default 1800,
range 30–604800); retries and process restarts preserve that deadline. Durable
Links retain their existing conditional-exit policy. Committed Links use WG
PersistentKeepalive of 25 seconds unless the static peer explicitly configures
another value. Initial negotiation confirms reachability; subsequent matching
PONGs refresh the control session. Babel detects routing-neighbor loss independently.

An omitted field that Velvet defines as derived still contributes its derived
value to desired state. A setting left to the kernel, such as an omitted route
metric, is neither written nor compared. Keepalive is derived at Link commit. Omitted route
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
every configured source prefix installs a `from` rule selecting that table and
a `to` rule selecting the Fabric table for return traffic. Fabric destination
rules run before Domain source rules. Configure the complete source set on
every participating forwarding node, with the same canonical prefix per family.
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

Access prefixes are ordinary return destinations: declare them in
`fabric.announcements` on the node providing local Access delivery. Keep business
exits in `domains.<name>.announcements`. Without Babel, configure remote Access
paths in `fabric.routes.<peer>` and business paths in `domains.<name>.routes.<peer>`;
announcements still provide local delivery through `throw` routes. With Babel,
the same announcements supply the next hops dynamically. Access interfaces and
their local delivery routes remain externally managed.

Routing admission comes from local configuration, not learned prefixes. There
is no catch-all Fabric lookup: packets outside the configured source and
destination selectors continue through the host's existing policy rules.
An arbitrary learned ordinary prefix outside those selectors does not create
a new destination rule. Explicit broad selectors, including `/0`, broaden this
scope. Fabric destination matches take precedence over Domain routes, rather
than comparing prefix lengths across the two tables.

Configurations that previously announced Access pools under a Domain should
move those announcements to `fabric.announcements`, and move static return
routes to `fabric.routes`. External return-selection rules are no longer needed.

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
configuration and automatically originates the node loopback. It attaches to
one independent Babel daemon and synchronizes configuration as Links change.
Fabric stopping or losing its control connection does not stop Babel. The
packaged systemd units restart each daemon independently; direct invocation
starts a detached Babel process and can restart it while Fabric is running.
Explicitly disabling Babel stops it before Fabric removes its managed routes.

The integration targets the exact Babel commit in `tests/babel-revision`. Configurations live in
`/var/lib/velvet/<uuid>/babel-rs.toml`; the control socket lives in
`/run/velvet-babel/<uuid>/babel-rs.ctl`. Configured static interfaces and committed
automatic interfaces enter Babel; tentative automatic interfaces do not.
Control-session loss preserves admission; deleting a Link removes admission.
Generated wired cost is 96. Fabric loopback host announcement metrics must be
multiples of 96, leaving the priority gap needed by neighbor fallbacks; ordinary
business announcements keep their existing metric range.

Within the same table and prefix, explicit static routes precede finite Babel
routes, then automatic neighbor loopback fallback routes (priority 131008),
then Babel unreachable routes (131070). Link subnet routes keep their existing
priority. This lets Babel route around a broken direct Link without requiring
Fabric to delete the neighbor fallback.

Full crash recovery requires a Babel build with FIB recovery support; older
v0.6.0 releases lack it. The accompanying Babel implementation defaults to clear
on normal exit and a 240-second startup recovery window after a crash. It adopts
old owned IPv4/IPv6 routes until fresh routes confirm them or their original
deadline expires; repeated crashes do not renew the deadline. Optional retain
exit is implemented in Babel but Fabric leaves the default clear policy enabled.
Build the updated Babel checkout alongside Fabric for this behavior. Remote
Babel timers still apply; this is not a guarantee of uninterrupted forwarding.

`babel-rs` uses UDP/6696 and `ff02::1:6` on every managed WireGuard interface.
It owns dynamic routes with protocol `203`; `velvetd` owns static routes and
rules with protocol `201` and adjacent routes with protocol `202`. Static and
dynamic routes share tables, with dynamic priorities placed after the complete
static metric range. Protocol values 201–203 are a Velvet-controlled ownership
namespace and must not be used by unrelated route managers in these tables.
Neither daemon writes learned routes to `main`.

## Dynamic Links

Dynamic Links are optional and require routed reachability between node
loopbacks; Babel is one way to provide that reachability, but the VFP procedure
does not depend on how the route was learned. The initial static Peers also
provide Endpoint Observations used by the baseline inference algorithm:

```json
{
  "dynamic_links": {
    "mode": "active",
    "allow_candidate_prefixes": ["192.0.2.0/24"]
  }
}
```

`active` discovers reachable non-adjacent nodes, proposes Links, and accepts
allowed proposals. `passive` only accepts proposals, while `off` disables both;
omitting the section is equivalent to `off`. The allow-list checks the IP of every remote candidate, including observer
offers. Nodes with Dynamic Links off can still serve bounded observer leases
through their existing Fabric sessions.

For each target, active mode maintains a continuing desire to establish a
Link. Ordinary failures retry with exponential backoff (10 seconds to a
five-minute base, plus 0–25% jitter). A policy rejection pauses proposals;
a separate UDP query budget checks again every five minutes plus jitter.
Versioned allowance updates make retries eligible without resetting backoff.
There is at most one live Attempt per peer, with at most four new routed dials
per second per node. An unavailable Fabric route pauses sends.

Admission uses VFP UDP between Fabric loopbacks, on the VFP port, protected by
the existing Fabric Links. Passive and off nodes keep this receiver: allowed
queries receive an update, denied queries are silent. Changed admission is
also pushed to known peers on effective reload. These are best-effort datagrams,
not a subscription or a global database. Policy replies have a five-second
per-peer cooldown and all policy sends share a 16-datagram budget per discovery
tick (normally once per second).
The bounded peer cache retains unreachable inactive peers for 30 minutes;
reload preserves its decisions and independent retry/query budgets.

The publisher revision is durably advanced before runtime startup/reload in
`/var/lib/velvet/<node-uuid>/dynamic-link-revision`. Preserve this counter with
the node identity. An invalid/unwritable counter prevents startup rather than
publishing an older revision. Receiver caches are in memory; after process
restart an unknown peer can be negotiated again within the local budget.

Each discovery task first exchanges baseline hints and fresh UDP receive keys
over routed VFP. Each endpoint then runs its own inference over local evidence,
exchanges bounded candidate batches, and sends encrypted one-way public UDP
probes. Observation reports return through Fabric; invalid and replayed probes
receive no response. Failed candidate rounds may actively measure the static
peer first, then other reachable observers. Observers only offer baseline
listeners and never recursively upgrade.

A reciprocal UDP path is handed to kernel WireGuard on the same local port.
The probe reserves a wildcard port across IPv4 and IPv6, matching WG's bind
scope. Packet metadata pins its measured source and restricts observations to
the selected local address; another address/family cannot share the reserved
port. The final close/rebind still fails cleanly if another process takes it.
WG first binds with empty AllowedIPs and keepalive=0; the peers exchange
WG_READY before enabling normal traffic. The Link commits only after the
regular link-local VFP establishment and target identity validation succeed.
No progress, budget exhaustion, control loss or handoff failure cleans tentative
resources and leaves the existing routed path in service. This is a bounded
first NAT traversal implementation, not exhaustive NAT support: arbitrary
random allocation and simultaneous destination-dependent mappings may fall back.

Dynamic interfaces are locally named `vdl-<remote-name>-<uuid-prefix4>` (or
`vdl-<uuid-prefix4>` without a remote name).

Normal shutdown, crashes and reloads retain committed Links. Private receipts
in `/var/lib/velvet/<uuid>/warm-links.json` bind each saved negotiation and last
confirmation to node identity, boot, namespace and interface generation.
Startup validates per-Link configuration and kernel key material, addresses
and AllowedIPs, then restores management and Babel admission without waiting
for a new PONG. Unrelated configuration changes do not invalidate Links.
Control health is reported separately as `active`; `committed` reports retained
forwarding state. Invalid receipts use ordinary cleanup and discovery and
never recreate missing interfaces. Across a host reboot, static configuration
and Durable agreements provide recovery.

## Durable Links

A healthy Dynamic Link can become Durable without changing its interface.
At least one side must observe its own listening port unchanged externally,
with its own advertised endpoint stable for 30 minutes. A qualifying side
proposes the fixed endpoint set over link-local TCP. If both sides qualify,
both endpoints are fixed. When only one is fixed, the other may change.
There are no bootstrap evidence levels or forced disconnect tests.

Optional `dynamic_links.durable` settings are `soft_limit` (default 2) and
`stable_seconds` (default 1800). Below the soft limit a node may propose
promotion. A recipient also accepts a proposer with no confirmed Durable Links,
so this is a soft limit, not a hard maximum. Saved and pending agreements
reserve capacity, including offline and Static-suppressed records.

Both peers save the same agreement and exchange saved confirmations. A local
record is confirmed only after local durable storage and the peer's confirmation.
An interrupted exchange retains saved recovery data and can retry; it does not
remove a healthy Link. State lives in `/var/lib/velvet/<node-uuid>/durable.json`,
with a version and explicit owner UUID/WireGuard public key. Corrupt or
incompatible state is reported and retained, never silently replaced with an
empty file.
Agreement IDs are UUID strings and public keys use standard WireGuard Base64.
Each record has local and peer sections; either or both may contain the recovery
endpoint fixed by the agreement. The peer's `last_loopback` is a mutable routed
VFP address cache, not part of the agreement or the persistent owner identity.

On startup Durable listeners restore independently of routed VFP. Automatic
recovery uses the fixed endpoints and saved ports. Once another Fabric path is
available, routed checks confirm that the peer still has the agreement and is
ready to receive. Checks run every 10 seconds with a 10-second request budget;
READY remains fresh for 30 seconds. Only 30 continuous minutes of direct
failure with both sides ready invalidate the agreement. Offline or unready
peers clear that timer. TCP reconnect alone does not reset a fresh READY period.
A changed fixed endpoint or an explicitly lost peer agreement invalidates it
immediately. An unchanged healthy Static takes priority over an automatic Link;
its standby Durable record continues to reserve capacity.

`off` invalidates all Dynamic/Durable resources and saved records. Static Peer
configuration remains authoritative. `velvetctl status` reports saved Durable
agreements; `velvetctl durable-delete --config node.json --peer <uuid>` deletes
one locally. A healthy Link can continue as Dynamic, but must complete a fresh
stability interval before another promotion.

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

Install all four files from [`packaging/systemd/`](packaging/systemd/) into
`/etc/systemd/system/`, run `systemctl daemon-reload`, then enable and start
`velvetd.service` and `velvet-recovery.timer`. Install `babel-rs` at the configured
path. Fabric enables and starts `velvet-babel@<uuid>.service` when routing is enabled; do not
start an additional standalone Babel service in that namespace.

Fabric reports systemd readiness after local initialization and uses completed
kernel maintenance to feed a 60-second watchdog. Remote PONG loss and Babel
unavailability do not prevent local readiness. Restart-on-failure preserves
committed resources. A separate timer checks persistent failure episodes,
stops the matching Babel service and removes this instance's kernel resources
when local recovery has failed for 30 minutes. Repeated restarts do not extend
the deadline; one minute of healthy maintenance ends the episode. Intentional
normal stops retain resources and do not start a retirement deadline.

Adjust `--recovery-window` and `--recovery-stable` in the Fabric unit's ExecStart
via a systemd override; adjust restart/watchdog settings there as needed.
If changing the configuration path, update both recovery commands as well.
The cleanup timer uses the recorded identity and tables even when configuration
cannot be loaded, holds the daemon's namespace lock, and preserves persistent
identity/configuration/Durable records. These guarantees require both Link
endpoints to run the updated Fabric behavior.

## Development and testing

Run local checks (the Babel supervisor tests launch a test child process and
use local Unix sockets; they do not require an installed Babel binary):

```sh
go vet ./...
go test -race ./...
go test ./internal/vfp/message -run '^$' -fuzz '^FuzzMessageDecode$' -fuzztime=5s -parallel=2
```

Keep inference input/output vectors in `internal/inference`. Runtime tests cover
Evidence storage, reservation cleanup and session identity; new algorithm
profiles can reuse these checks. Add a new network topology when it exercises
new transport or NAT behavior.

The first transport-independent Infer/search implementation is tested against
deterministic NAT models in `internal/linkdiscovery`. These simulations run in
the normal Go test suite and CI. The daemon uses a per-node loop and real
VFP/UDP adapters, which need their own integration coverage. See [algorithm and network testing](tests/README.md)
for coverage, commands, and model limitations.

The privileged Linux E2E suite under `tests/e2e/` creates disposable network
namespaces. It covers adjacent unnumbered Links, static Core reconciliation and
CRUD, and an eight-node, eight-Link, two-Domain topology. The dynamic test first
uses no static multi-hop routes and verifies Babel convergence, then restarts
the same sparse Core with Dynamic Links enabled and requires a complete
eight-node mesh. It checks all node loopbacks, Domain forwarding, route
selection over the new direct Links, child withdrawal/restart, and reload
preservation. The same suite runs in GitHub Actions.

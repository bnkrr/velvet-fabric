# Endless mixed public/NAT E2E (opt-in)

Real velvetd and managed Babel processes run in isolated Linux namespaces.
Every node is either public or behind a controlled UDP NAT. Each newly added
node selects **one currently present public node** as its outbound bootstrap.
Public nodes also participate in deletion/re-add; at least one remains present.
The harness does not restart or reload surviving nodes to reset discovery state.

```sh
tests/endless/run-on-vm.sh --nodes 16 --min-nodes 8 --rounds 0
tests/endless/run-on-vm.sh --nodes 16 --min-nodes 8 --rounds 0 --underlay ipv6
# Bounded execution of the same loop:
tests/endless/run-on-vm.sh --nodes 4 --rounds 6 --stable-seconds 3
```

`--rounds 0` continues until verifier failure or interruption. The endless
runner is **not** included in normal E2E `all` or automatically launched by CI;
only its unprivileged verifier tests run in CI. Root, Linux netns/WireGuard,
Python 3.11+, iproute2, nftables, ping and sysctl are required on the test host.

The wrapper builds locally, including pinned **babel-rs v0.4.1** at
`b5e15d857d776c60179dcb6078a524b56b3ced94`, using a Git archive rather than sibling
worktree edits. Only binaries/runtime files are copied into a unique asset
directory on the configured VM. Overrides: `VELVET_GO_BIN`, `VELVET_SSH_CONFIG`,
`VELVET_VM_HOST`, `VELVET_VM_REMOTE_ROOT`.

## Per-node underlay model

There are `max(2, nodes // 4)` public slots: four in a 16-slot pool. Remaining
slots each have their own LAN, router namespace and protocol-agnostic NAT
process. NAT attributes are independent:

| Axis | Values |
| --- | --- |
| Mapping | EIM (local endpoint); ADM (local endpoint + destination address); APDM (local endpoint + destination address/port) |
| Filtering | EIF (any external source); ADF (previously contacted address); APDF (previously contacted address/port) |
| Port allocation | Preserve, fixed offset, sequential, random |

The 36 combinations are spread across initial NAT slots and rotated when a NAT
slot is added again. A finite pool cannot contain all 36 at once; the manifest
and per-birth events record actual coverage. A slot retains its public/NAT role,
but no public slot is protected from deletion except the last present public.
Identity/key/loopback remain stable across re-add; NAT mapping state is recreated.

The NAT fixture receives real LAN Ethernet/UDP packets via AF_PACKET, allocates
real external UDP sockets according to its mapping function, applies its filter
to external source endpoints, and injects replies with the original remote
IP/port and valid IP/UDP checksums. Kernel forwarding is suppressed to prevent
an untranslated bypass. It treats payloads as opaque: **no VFP/WireGuard parsing,
synthetic evidence or knowledge of expected connectivity**. Each mapping expires
after 180 idle seconds. Mapping count and destination history per mapping are
bounded at 4096; overflow fails the fixture. Allocation collisions fall back to
a free kernel port and thus need not preserve the original allocation pattern.

This is a controlled packet-level NAT emulator, not a claim that Linux SNAT or
every commercial router exhibits all these profiles. The existing deterministic
kernel NAT44/NAT66 E2E suite remains complementary. IPv6 mode uses only IPv6
underlay endpoints and translates private IPv6 addresses to public fixture IPv6
addresses. Public addresses are documentation ranges on an isolated bridge,
not Internet listeners. Fragmentation, IPv6 extension headers, TCP NAT,
hairpinning, NAT64/NPTv6 and multi-layer NAT are outside this fixture's scope.

## Bootstrap provisioning

Every public has preprovisioned per-slot WG receiver interfaces with known peer
keys. NodeSpec currently requires an endpoint hint, so unused receivers point at
an unoccupied documentation address; only authenticated WG roaming learns an
actual member endpoint. This does not create static Links to every public.
A node's one outbound `vl-boot-PP` connects to the selected public's `vl-in-NN`.
Bootstrap interface names sort before the zero-padded inbound receiver names,
so the runtime tries the selected public bootstrap as an observer first.
Public nodes retain their inbound receivers when they themselves bootstrap
through another public. Existing members may reconnect to a returning public,
so parallel provisioned Links between two publics are possible and valid.

Initial public slots start first, forming a connected provisioned graph by
selecting an already introduced public. Other nodes then choose among them.
On every later add the selection is made from the current live public set,
including when a returning member's previous public is still alive. The host
model owns this selection; the test does not infer desired membership from WG
or Babel's current observations.

A closed provisioned VFP session must withdraw its materialized adjacency route
and evidence while preserving its configured bootstrap WG interface. Otherwise
an old public's protocol-202 route would blackhole traffic after a member changes
bootstrap. Static committed counts reflect current materialized sessions; unused
public receiver interfaces intentionally do not count as established.

## Verifier and convergence

Every audit reads every active member's kernel FIB, actual WG public/peer keys,
handshake timestamps, AllowedIPs, runtime committed counts and process state.
The independent model requires:

- Correct, reciprocal provisioned Links for the selected bootstrap graph.
- With Dynamic Links enabled, direct connectivity among live public nodes.
- Additional NAT/public and NAT/NAT Links may succeed or retain a routed fallback.
  At least one committed NAT Dynamic Link is required while multiple publics
  and NAT nodes are present, so an all-static run cannot pass as NAT punching.
  This permits bounded inference failure without incorrectly demanding a full
  mesh from arbitrary NAT combinations. Any tentative/stale WG interface, missing
  handshake or incomplete AllowedIPs prevents successful convergence.
- All modeled reachable destinations have active routes using live WG peers.
  Following each best FIB path must reach its owner without cycles. Public/public
  pairs use their required direct Links; NAT paths may traverse public nodes.
  Removed destinations must leave no unicast learned/materialized route behind.
- Remote overlay routes never leak into `main`; the local connected loopback and
  ordinary NAT-client underlay default route are allowed.
- Real IPv6 loopback pings rotate over ordered reachable pairs; a removed node
  must not answer. With dynamic disabled, reachability follows the provisioned
  graph and deletion may partition it.
- Exactly one velvetd and one managed Babel process per member, with no unexpected
  replacement or orphan after deletion. The supervisor's temporary Babel `check`
  process is identified by its parent, executable and exact config arguments;
  it must exit before the stable window can complete. Other extra processes fail.
  NAT process liveness and fresh status
  are also checked, separately from the member's processes.

NAT fallback can traverse the member being removed, so survivor forwarding may
reconverge within the same finite phase deadline. Unlike the former all-public
full-mesh fixture, this harness does not assume every survivor path is unaffected.
Transient mismatches reset the stable window; a phase that never converges fails.
A VFP recovery deadline is not the entire failure-detection deadline: TCP failure
detection happens first. Production timers are retained, not shortened by tests.

| Option | Default | Meaning |
| --- | --- | --- |
| `--nodes` | 6 | Total reusable slots, at most 16 |
| `--min-nodes` | 3 | Require `3 <= min-nodes < nodes`; includes public slots |
| `--seed` | 1 | Repeatable topology, bootstrap, profile and add/delete sequence |
| `--rounds` | 0 | Mutation rounds; zero is unlimited, startup is round 0 |
| `--underlay` | ipv4 | IPv4 NAT/public or IPv6 NAT/public |
| `--dynamic` | active | `active` or provisioned-graph-only `off` |
| `--settle-timeout` | 180 | Budget for startup/mutation and each convergence phase |
| `--stable-seconds` | 10 | Required continuous successful audit interval |
| `--probe-pairs` | 16 | Rotating positive ping pairs per audit |
| `--rss-growth-mib` | 64 | Allowed per-process rolling median RSS growth |
| `--artifacts` | unique run directory | Must not already exist |

## Records, resources and stopping

The finite slot pool bounds state. Per current process, RSS samples use a
60-entry deque. After five minutes and 60 samples, a rolling median becomes its
baseline; subsequent growth beyond the configured allowance fails. FD budgets
are `64 + 16 * nodes` for member processes and 4112 for a NAT process. A short
run does not establish an RSS plateau or prove leak freedom.

Artifacts use umask 077:

- Manifest: arguments, initial topology/profiles, binary hashes, Python/kernel
  versions, runner PID, unique `vfe-...` namespace prefix, bridge and UUIDs.
- Exact copied `netns.py`, `model.py`, `nat.py` runtime sources.
- Rotating `events.jsonl` (about 16 MiB with backups), `samples.jsonl` (about
  2 MiB), per-slot daemon logs (about 2 MiB per slot).
- Atomically replaced `latest.json` with current topology and complete audit.
- On failure/interruption: `failure.json`, bounded-time WG/kernel/socket/control
  diagnostics, NAT state/error records, configs and Babel state. Configs contain
  test credentials; raw WG private/preshared keys are discarded from observations.

Same seed/options/runtime reconstruct the event sequence, not identical packet
scheduling or cryptographic randomness. Preserve failed-round records and binaries.
No per-round archive grows indefinitely. Externally redirecting stdout needs its
own rotation; it is a live progress stream in addition to rotating event files.

The wrapper uses an SSH PTY: keep that session open or run in a persistent VM
session. It does not create a background process itself. SIGINT/SIGTERM/SIGHUP
request cleanup after current bounded-operation ownership tracking; a successful
interrupted cleanup exits 130. Finite successful completion exits 0. Setup,
verifier or cleanup errors exit nonzero. No auto-restart hides the first failure.
SIGKILL/VM failure cannot perform cleanup. Cleanup touches only this run's
recorded nodes, NAT routers, veths, bridge, processes and UUID directories.

## Checking the checker

```sh
# No root/network, reproducible plan:
tests/endless/run-on-vm.sh --plan --nodes 16 --min-nodes 8 --rounds 10
# Negative controls and model/NAT framing unit tests:
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/endless -v
# Root-only, independent real UDP tests for all 36 profiles in each family:
sudo env PYTHONDONTWRITEBYTECODE=1 python3 tests/endless/check_nat.py
# Retained namespace references and SIGTERM during partial setup:
sudo env PYTHONDONTWRITEBYTECODE=1 python3 tests/endless/check_lifecycle.py \
  /absolute/path/to/velvetd /absolute/path/to/babel-rs \
  --nodes 4 --artifacts /absolute/path/to/new-run
# Actual WG handoff with final VFP deliberately blocked: Babel must exclude
# the tentative Link throughout, then forwarding must retain the routed path.
sudo env PYTHONDONTWRITEBYTECODE=1 python3 tests/endless/check_commit.py \
  /absolute/path/to/velvetd /absolute/path/to/babel-rs \
  --nodes 4 --artifacts /absolute/path/to/new-commit-run
```

The real UDP check independently varies destination IP, destination port and
local port, observes actual translated endpoints, tests unsolicited replies from
different external endpoints, and relies on kernel UDP delivery to validate
reply framing/checksums. It supplies no Velvet protocol messages.

## VM test configuration

Set `VELVET_VM_HOST` to your SSH destination and `VELVET_VM_REMOTE_ROOT`
to an absolute test asset directory. For Babel suites, set `VELVET_BABEL_REPO`
to a local Git checkout containing the pinned revision. Go and Cargo are
resolved through PATH; `VELVET_GO_BIN` and `VELVET_CARGO_BIN` can override
them. `VELVET_SSH_CONFIG` optionally selects an SSH configuration file.
Use a Linux build host with a matching VM architecture. Keep personal
defaults outside tracked files; configure caches/toolchains in the caller environment.

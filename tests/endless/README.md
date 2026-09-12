# Endless mixed public/NAT E2E (opt-in)

Real velvetd and managed Babel processes run in isolated Linux namespaces.
Every node is either public or behind a controlled UDP NAT. Each newly added
node selects **one currently present public node** as its outbound bootstrap.
Public nodes also participate in deletion/re-add; at least one remains present.
Membership churn does not restart or reload surviving nodes to reset discovery
state. Explicit online exercises below change only the selected fault/policy.

```sh
tests/endless/run-on-vm.sh --nodes 16 --min-nodes 8 --rounds 0
tests/endless/run-on-vm.sh --nodes 16 --min-nodes 8 --rounds 0 --underlay ipv6
# Bounded execution of the same loop:
tests/endless/run-on-vm.sh --nodes 4 --rounds 6 --stable-seconds 3
# Online changes, followed by one membership mutation (still finite):
tests/endless/run-on-vm.sh --nodes 4 --rounds 1 --capture \
  --exercise policy --exercise blackout --exercise control-loss \
  --exercise nat-reset --exercise nat-rebind
# Public nodes must initiate toward passive NAT members, including NAT66:
tests/endless/run-on-vm.sh --nodes 16 --min-nodes 8 --rounds 4 \
  --underlay ipv6 --nat-policy passive
```

`--rounds 0` continues until verifier failure or interruption. The endless
runner is **not** included in normal E2E `all` or automatically launched by CI;
only its unprivileged verifier tests run in CI. Root, Linux netns/WireGuard,
Python 3.11+, iproute2, nftables, ping and sysctl are required on the test host.
Run finite regressions serially on a small VM: namespace isolation does not
isolate CPU or kernel work, and parallel suites can exhaust the 5s tool budget.

The wrapper builds locally, including pinned **babel-rs v0.6.0** at
`dbeede34abd8dff2422c39ab18a15949b0f38f11`, using a Git archive rather than sibling
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

An expired provisioned Link must withdraw its materialized adjacency route
and evidence while preserving its configured bootstrap WG interface and local addresses. Otherwise
an old public's protocol-202 route would blackhole traffic after a member changes
bootstrap. Static committed counts reflect current live adjacencies; unused
public receiver interfaces intentionally do not count as established.

## Verifier and convergence

Every audit reads every active member's kernel FIB, actual WG public/peer keys,
handshake timestamps, AllowedIPs, runtime committed counts and process state.
The independent model requires:

- Correct, reciprocal provisioned Links for the selected bootstrap graph.
- With Dynamic Links enabled, every public/public and public/NAT pair with
  `A.want(B) && B.accept(A)` or the reverse must have a direct Link. All fixture
  profiles can send to a public listener; other successful NAT pairs cannot
  hide one missing pair. Static bootstrap Links remain required in every mode.
- NAT/NAT pairs may use direct Links or routed fallback. Every committed WG
  interface must have a reciprocal peer of the correct interface kind, an actual
  handshake and complete AllowedIPs. A provisioned peer using the same node key
  cannot stand in for the reciprocal end of a Dynamic Link.
- Continual attempts may coexist with valid fallback. Before starting each node,
  the verifier subscribes to kernel route and interface events. Installation of
  a protocol-202 adjacency in table 20000 records materialization for that kernel
  ifindex. Replacing the same peer route onto a parallel static or dynamic Link
  does not erase this record; interface deletion does. Lost/truncated events fail
  verification. A dynamic incarnation never materialized must carry no FIB route
  and have no Babel UDP socket. This evidence is independent of daemon up claims;
  a tentative incarnation lasting over 90 seconds fails (30s UDP + 30s final
  validation + 10s deferred cleanup + 5s cleanup, with 15s sampling allowance).
  Such interfaces never satisfy required neighbors or committed counts.
- All modeled reachable destinations have active routes using live WG peers.
  Following each best FIB path must reach its owner without cycles. Public/public
  and public/NAT pairs use required direct Links; optional NAT/NAT paths may
  traverse public nodes.
  Removed destinations must leave no unicast learned/materialized route behind.
- Remote overlay routes never leak into `main`; the local connected loopback and
  ordinary NAT-client underlay default route are allowed.
- Real IPv6 loopback pings rotate over ordered reachable pairs; every pair must
  actually pass during each verification phase in addition to the continuous
  stable audit window. A removed node
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
A Dynamic Link recovery deadline is not the entire failure-detection deadline:
the 30-second Link-local UDP liveness budget comes before the additional 30-second
recovery window. TCP negotiation closes on completion and does not own established
Link liveness. Production timers are retained, not shortened by tests.

| Option | Default | Meaning |
| --- | --- | --- |
| `--nodes` | 6 | Total reusable slots, at most 16 |
| `--min-nodes` | 3 | Require `3 <= min-nodes < nodes`; includes public slots |
| `--seed` | 1 | Repeatable topology, bootstrap, profile and add/delete sequence |
| `--rounds` | 0 | Membership rounds after exercises; zero is unlimited, startup is round 0 |
| `--underlay` | ipv4 | IPv4 NAT/public or IPv6 NAT/public |
| `--dynamic` | active | `active` or provisioned-graph-only `off` |
| `--nat-policy` | active | Initial NAT policy, `active` or `passive`; publics stay active |
| `--exercise` | none | Repeat option for distinct online exercises; each runs once before churn |
| `--capture` | disabled | Rotating UDP capture on this run's bridge; requires tcpdump |
| `--settle-timeout` | 180 | Budget for startup/mutation and each convergence phase |
| `--stable-seconds` | 10 | Required continuous successful audit interval |
| `--probe-pairs` | 16 | Rotating positive ping pairs per audit |
| `--rss-growth-mib` | 64 | Allowed per-process rolling median RSS growth |
| `--artifacts` | unique run directory | Must not already exist |

## Bounded online exercises

These exercises select the first NAT member and a public other than its bootstrap.
They run after initial convergence and before the requested membership rounds.
They are explicit, deterministic fault cases, not yet randomized churn events.

| Exercise | Injection and independent acceptance |
| --- | --- |
| `policy` | SIGHUP off → passive → original policy. First require old dynamic interfaces to retire within 75s, then require no proposals to/from that node for 18s. Passive must not initiate. Required public links recover. Current SIGHUP replaces the target's runtime/Babel; only that child replacement is allowed, and the old PID must disappear. |
| `blackout` | Drop one direction of underlay UDP for one established non-bootstrap public/NAT pair for at least 40s. Require withdrawn direct routes and real bidirectional fallback before removing the fault, then recover direct connectivity. |
| `control-loss` | Block the pair's routed TCP/UDP VFP port, remove only that pair's dynamic WG interfaces and hold at least 20s. Verify actual dropped packets and fallback; restore control and require fresh direct Links. |
| `nat-reset` | Replace only the translator, clearing all mappings while member/Babel stay alive. The replacement must forward real traffic and all required direct paths recover. |
| `nat-rebind` | Clear mappings, change the router WAN address and switch preserve/offset allocation. Public WG observations must use the new WAN endpoint; all required paths recover without restarting velvetd/Babel. |

Fault windows and recovery phases are separate. The recovery budget and production
retry timers are unchanged. Packet counters prove the injected drop matched real
traffic. Except for the explicitly reloaded policy target's managed Babel, all
existing velvetd/Babel PIDs must remain unchanged. These cases do not claim broad
partition, dual-stack switching, multi-layer NAT or all observer-failure coverage.

## Records, resources and stopping

The finite slot pool bounds state. Per current process, RSS samples use a
60-entry deque. After five minutes and 60 samples, a rolling median becomes its
baseline; subsequent growth beyond the configured allowance fails. The base FD
budget is `64 + 16 * nodes`, where `nodes` is the configured slot count. Velvetd
also allows `3 * min(128, max(0, (nodes - 1) * (nodes - 2)))` FDs for the bounded
observer pool: each lease can add one routed TCP connection and two UDP listeners.
Babel uses only the base budget; a NAT process has a separate limit of 4112.
A short run does not establish an RSS plateau or prove leak freedom.

The old per-Link-only estimate under-counted shared public observers during
simultaneous discovery. The real observer-concurrency regression in
`tests/directed/` also drains leases and requires all temporary public UDP/routed
TCP sockets to close and FDs to return below the original per-Link ceiling,
in addition to the normal shutdown ownership audit.

Each NAT translator publishes a heartbeat on the shared host monotonic clock.
A heartbeat older than five seconds fails verification; wall-clock corrections
do not change this budget or depend on status-file modification times.

Artifacts use umask 077:

- Manifest: arguments, initial topology/profiles, binary hashes, Python/kernel
  versions, runner PID, unique `vfe-...` namespace prefix, bridge and UUIDs.
- Exact copied `netns.py`, `model.py`, `nat.py`, `coverage_model.py`, `mutations.py`
  runtime sources.
- Rotating `events.jsonl` (about 16 MiB with backups), `samples.jsonl` (about
  2 MiB), per-slot daemon logs (about 2 MiB per slot).
- Atomically replaced `latest.json` with current topology and complete audit.
- `coverage.json`: cumulative verified samples by family/profile/policy/requirement/
  outcome, latest ordered node pairs, actual ping and local/remote proposal counts.
  Pair counts reset on birth or NAT replacement; sampled outcome does not invent
  an initiator when no proposal was observed. A finite run reports only the
  profiles actually verified, not all 36 merely because they exist in the catalog.
- Rotating `observations.jsonl` (about 12 MiB): intermediate kernel WG counters,
  routes, Babel sockets and actual ifindices, including partial reads before a
  later node fails. Each sample and daemon log carries host-monotonic elapsed
  time and round; events also identify the current exercise phase.
- Optional `underlay.pcap*` (3 × about 10 MB, 256-byte snapshot length). Capture
  startup and continued process liveness are checked; `capture.log` retains
  tcpdump's final packet/drop statistics. This captures underlay UDP only.
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
# Root-only, real route replacement between parallel Links, interface recreation,
# and rejection of premature Babel routes (also part of hosted E2E CI):
sudo env PYTHONDONTWRITEBYTECODE=1 python3 tests/endless/check_materialization.py
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

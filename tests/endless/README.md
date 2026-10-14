# Endless mixed public/NAT E2E (opt-in)

Real velvetd and managed Babel processes run in isolated Linux namespaces.
Every node is either public or behind a controlled UDP NAT. Each newly added
node selects **one currently present public node** as its outbound bootstrap.
Public nodes also participate in deletion/re-add; at least one discovery listener
per tested address family remains present.
Membership churn does not restart or reload surviving nodes to reset discovery
state. Explicit online exercises below change only the selected fault/policy.

Configure the test host and local build environment using [VM setup](../VM.md).
The default underlay is dual stack: every public node, NAT router and member LAN
has both IPv4 and IPv6 addresses. `--underlay ipv4` or `--underlay ipv6` retains
the single-family regressions.

Dynamic discovery tests same-family candidate pairs. In dual mode, separate IPv4
and IPv6 discovery groups share a dual-stack underlay and connect through two
Static-only transit slots. Same-family public/public and public/NAT direct Links
remain required within an already routed component. Cross-family groups use
Babel transit when the configured
bootstrap graph connects them. Choosing a common discovery family from disjoint
initial candidates is outside this endurance test; the endpoint matrix separately
checks forwarding during such a failed attempt.

```sh
tests/endless/run-on-vm.sh --nodes 16 --min-nodes 8 --rounds 0
tests/endless/run-on-vm.sh --nodes 16 --min-nodes 8 --rounds 0 --underlay ipv6
# Detach on the VM; progress stays in the run's rotating events.jsonl:
tests/endless/run-on-vm.sh --detach --nodes 8 --rounds 0 --exercise durable
# Dual-stack underlay and external WG Access clients; stop after eight hours:
tests/endless/run-on-vm.sh --detach --nodes 10 --min-nodes 6 --rounds 0 --exercise durable \
  --underlay dual --wg-access --duration-seconds 28800
# Bounded execution of the same loop:
tests/endless/run-on-vm.sh --nodes 8 --rounds 6 --stable-seconds 3
# Bilateral endpoint inputs, packet loss, and real timeout-driven fallback:
tests/endless/run-on-vm.sh --endpoint-matrix --wg-access
# Reproduce one case without the rest of the matrix:
tests/endless/run-on-vm.sh --endpoint-matrix --endpoint-case live4/6 --wg-access
# Online changes, followed by one membership mutation (still finite):
tests/endless/run-on-vm.sh --nodes 8 --rounds 1 --capture \
  --exercise policy --exercise blackout --exercise control-loss \
  --exercise nat-reset --exercise nat-rebind
# Public nodes must initiate toward passive NAT members, including NAT66:
tests/endless/run-on-vm.sh --nodes 16 --min-nodes 8 --rounds 4 \
  --underlay ipv6 --nat-policy passive
```

`--rounds 0` continues until verifier failure or interruption. The endless
runner is **not** included in normal E2E `all` or automatically launched by CI.
CI runs its unprivileged verifier tests and the finite kernel materialization
check. Root, Linux netns/WireGuard,
Python 3.11+, iproute2, nftables, ping and sysctl are required on the test host.

`--duration-seconds` adds a total wall-clock budget (default zero: unlimited),
including setup and exercises. At expiry the runner stops starting/checking
operations and performs normal cleanup; the current command may take up to its
existing bounded timeout. Cleanup may finish a little after the deadline. VM
sleep counts toward the wall-clock budget; after resume an expired run cleans
up. Earlier verifier failures still fail immediately. A timed run succeeds only
if at least one round was verified; its completion record names the last
verified round, without claiming the interrupted membership change passed.

`--wg-access` provisions an external client namespace and separate WireGuard
keys/interface per member, recreated with that member during churn. Both IPv4
and IPv6 clients traverse the real WG Access tunnel to remote node services;
services also initiate probes back to clients. Velvet owns only the Domain and
Fabric routing policies: the fixture adds no return selector or NAT workaround.
Client prefixes are ordinary Fabric announcements; service prefixes are Domain
announcements. The verifier checks managed destination selectors, live route
sets, real return-table selection, WG identities/AllowedIPs and handshakes,
exclusion of Access from Babel, and ordinary host routing isolation. Each
verified member pair must also pass both Access directions in both families;
`access_probes` counts successful Access pings. Client namespaces are included
in removal and final cleanup, under the same run-owned prefix. This models
external WG Access without changing Velvet Core into an Access provisioner.
Run finite regressions serially on a small VM: namespace isolation does not
isolate CPU or kernel work, and parallel suites can exhaust the 5s tool budget.

The wrapper builds locally, including the Babel commit from
`tests/babel-revision`, using a Git archive by default. Explicit paired development
uses `VELVET_BABEL_SOURCE=working-tree`. Only binaries/runtime files are copied into a unique asset
directory on the configured VM. Build and SSH settings are shared with the
other suites; see [VM setup](../VM.md).

## Per-node underlay model

Dual dynamic mode requires at least eight slots and defaults to eight: public
slots 0–1 provide Static transit with dynamic mode `off`; public slots 2/4 use
IPv4 discovery, and 3/5 use IPv6. NAT slots 6 onward alternate the two families.
Every namespace still has both underlay families. The assigned discovery family
stays fixed across births, including saved Durable recovery. Single-family and
Static-only modes default to six slots, with `max(2, nodes // 4)` public slots.
Each NAT slot has its own LAN, router namespace and protocol-agnostic translator.
Use at least ten slots to include same-family NAT/NAT pairs in both groups.
NAT attributes are independent:

| Axis | Values |
| --- | --- |
| Mapping | EIM (local endpoint); ADM (local endpoint + destination address); APDM (local endpoint + destination address/port) |
| Filtering | EIF (any external source); ADF (previously contacted address); APDF (previously contacted address/port) |
| Port allocation | Preserve, fixed offset, sequential, random |

The 36 combinations are spread across initial NAT slots and rotated when a NAT
slot is added again. A finite pool cannot contain all 36 at once; the manifest
and per-birth events record actual coverage. A slot retains its public/NAT role,
and all slots can leave/rejoin. Churn preserves the last public discovery
listener in each family (the last public in single-family mode). Transit slots
can both disappear; expected components follow configured Static Links and
previously verified automatic Links whose endpoints have survived. New Dynamic
negotiation requires an existing routed path: sharing a discovery family alone
does not join partitions. Removing/recreating a node or setting its mode to
`off` retires its automatic edges; losing an intermediate bootstrap does not.
Full routes and payload checks apply within each component, and a rotating cross-component
probe must fail. Current route tables and advertised neighbor counts never
define expected components. Bilateral automatic recovery (including Durable)
can expand them only with active, committed, materialized WG interfaces on both
ends, reciprocal keys, handshakes and complete AllowedIPs. A saved record alone
cannot join partitions. Missing observations cannot shrink expectations; unused
edges are retired only after the full route and payload audit succeeds.
Control-session loss alone does not discard previously verified forwarding.
`--plan` assumes required Links pass; it does not predict optional NAT/NAT Links.
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
The translator raises its own file-descriptor soft limit to 4160 when needed,
within the inherited hard limit; an insufficient hard limit fails at startup.
This does not change the limits of velvetd or Babel. `check_nat.py` verifies real
traffic through more than 1024 retained mappings in IPv4, IPv6 and dual mode,
starting each capacity-test translator with a soft limit of 1024.

This is a controlled packet-level NAT emulator, not a claim that Linux SNAT or
every commercial router exhibits all these profiles. The existing deterministic
kernel NAT44/NAT66 E2E suite remains complementary. In dual mode one translator
handles NAT44 and NAT66 simultaneously, with separate mappings and sequential
port allocation per family. Single IPv6 mode uses only IPv6 endpoints. IPv6 NAT
translates private fixture IPv6 addresses to public fixture IPv6 addresses;
it does not translate between address families. Public addresses are documentation ranges on an isolated bridge,
not Internet listeners. Fragmentation, IPv6 extension headers, TCP NAT,
hairpinning, NAT64/NPTv6 and multi-layer NAT are outside this fixture's scope.

## Bootstrap provisioning

Every public has preprovisioned per-slot WG receiver interfaces with known peer
keys. Receivers for NAT slots have empty endpoint lists: only authenticated WG
roaming learns the actual translated address/port. In dual mode public/public
receivers also get endpoint hints for the peer's known outbound listening port.
Hints alone cannot establish a Link to a different bootstrap's cryptographic
receiver. This does not create static Links to every public.
A node's one outbound `vl-boot-PP` connects to the selected public's `vl-in-NN`.
Between transit slots (and in Static-only dual mode), each side independently
rotates hints by slot and birth: IPv4 only, IPv6 only, IPv4 then IPv6, IPv6 then
IPv4. Links involving a discovery-group member use that group's family, and
its allowed discovery prefix is restricted accordingly. A member chooses a
bootstrap from its own group or a transit slot; a transit slot can choose any
public. Kernel endpoint audits enforce those fixture inputs. The peer's birth
does not rewrite a surviving node's configuration. `node-start.endpoint_hints`
records input lists separately from actual WG selection and roaming.
Bootstrap interface names sort before the zero-padded inbound receiver names,
so the runtime tries the selected public bootstrap as an observer first.
Public nodes retain their inbound receivers when they themselves bootstrap
through another public. Existing members may reconnect to a returning public,
so parallel provisioned Links between two publics are possible and valid.

Initial public slots start first, forming a connected provisioned graph by
selecting an already introduced public. Other nodes then choose among them.
On every later add the selection is made from the current live public set,
subject to the family constraints above, even when its previous public is still
alive. The host model owns this selection; the test does not infer desired membership from WG
or Babel's current observations.

A control-expired committed Link retains its WG interface, addresses, Babel
admission and protocol-202 neighbor fallback at priority 131008. Finite Babel
routes must beat obsolete fallbacks when a member changes bootstrap. Established
counts describe live control sessions; retained interfaces are audited separately
against fixture identities and observed kernel materialization.

## Bilateral endpoint matrix

`--endpoint-matrix` runs a finite suite on four public dual-stack nodes, independent
of membership churn. Each case starts with fresh namespaces and WG sessions.
Two spokes continuously carry IPv4 and IPv6 underlay traffic; the tested pair
has only its one provisioned path. Optional `--wg-access` also checks both payload
families in both directions. Select cases with repeatable `--endpoint-case`.

The matrix covers passive/4, passive/6, 4/4, 6/6, 4/6, 6/4, opposite dual-list
orders, an unavailable first IPv4 or IPv6 candidate, all candidates unavailable
followed by recovery, and established IPv4-to-IPv6 and IPv6-to-IPv4 fallback.
Both mixed single-candidate configurations are also faulted after roaming, to
verify that the surviving configured address is retried without a second entry.
Mixed hints need not remain asymmetric after authenticated WG roaming. Fault
counters must prove dropped packets. All-down must have no handshake or successful
payload; recovery must then pass the full FIB/identity/traffic audit.

Live failover never reloads configuration or restarts either daemon. It allows
300 seconds for the existing 180-second stale-handshake threshold, 15-second
candidate rotation, and link/routing recovery. `endpoint-matrix.json` records
the hints, final endpoints, traffic counter deltas, fault hits and recovery times.

The final `dynamic-mixed-fallback` case gives two spokes disjoint observed
candidate families and enables dynamic discovery between them. It requires
terminal failed attempts plus verified bidirectional Babel transit through the
hub. Its recorded outcome explicitly names the unsupported dynamic case. This
checks that discovery failure preserves forwarding. The membership run separately
requires all eligible same-family direct Links.

## Verifier and convergence

Every audit reads every active member's kernel FIB, actual WG public/peer keys,
handshake timestamps, AllowedIPs, runtime committed counts and process state.
It also reads atomic Durable files, validates their owner UUID/public key,
checks peer keys against fixture identities, and compares agreement/recovery endpoint
sets with runtime status and the other side's record when present. A saved record
is not proof of an active Link. Confirmed Durable records and active Dynamic Links
are counted separately; coverage distinguishes `static`, `dynamic`, `durable`
and `fallback` outcomes.
The coverage matrix retains the configured `family` mode and adds the actual
`endpoint_family` of the selected first WG hop, including routed fallback.
In dual mode each successful payload probe samples the kernel route and WG peer
before and after the loopback ping and optional dual-stack Access probes. Only
an unchanged selected interface, peer and endpoint with a handshake and increased
TX counts increments `endpoint_probes.ipv4` or `.ipv6`. RX may stay unchanged
when Babel chooses another return path; reverse ordered probes independently
check the other direction. Path changes or counter resets invalidate the sample.
Both counters must be nonzero before any round can pass;
merely configuring two addresses or observing two endpoints is insufficient.
These counters describe the source's selected first hop, not every hop of a
possibly mixed-family routed path. Later rounds may legitimately use only one
family while nodes are absent; the counters are cumulative across the run.
The independent model requires:

- Correct, reciprocal provisioned Links for the selected bootstrap graph.
- With Dynamic Links enabled, every public/public and public/NAT pair with
  `A.want(B) && B.accept(A)` or the reverse must have a direct Link within each
  discovery family and already routed component. Cross-family reachability
  requires a configured transit path.
  All fixture profiles can send to a public listener; other successful NAT pairs cannot
  hide one missing pair. Static bootstrap Links remain required in every mode.
  Matching saved receivers on both live peers may use verified routed fallback
  during Durable's controlled recovery window. The host tracks this per agreement
  for at most 30 minutes plus 90 seconds of cleanup/re-discovery allowance; it
  resets on peer departure or actual reconnection, not on repeated observations.
  A one-sided record or an absent receive interface cannot grant this allowance.
  Coverage labels these samples `durable-recovery` rather than claiming a direct Link.
- NAT/NAT pairs may use direct Links or routed fallback. Every committed WG
  interface must have a reciprocal peer of the correct interface kind, an actual
  handshake and complete AllowedIPs. A provisioned peer using the same node key
  cannot stand in for the reciprocal end of a Dynamic Link.
- Continual attempts may coexist with valid fallback. Before starting each node,
  the verifier subscribes to kernel route and interface events. Installation of
  a protocol-202 adjacency in table 20000 records materialization for that kernel
  ifindex. Replacing the same peer route onto a parallel static or dynamic Link
  does not erase this record; interface deletion does. Lost/truncated events fail
  verification. A background reader continuously consumes each socket while
  status queries and payload probes run. Snapshots synchronize with that reader;
  any loss remains a fatal error on subsequent reads. The root fixture requests
  a 16 MiB receive limit and checks the effective kernel value (32 MiB including
  accounting), using a per-socket override if the system limit clamps it. This
  accommodates the 20,000-event burst with its kernel skb overhead; queue memory
  is allocated on demand. A reusable datagram buffer avoids allocating 1 MiB
  for every small notification. It does not change host sysctls. Batches yield
  between reads instead of treating 4,096
  queued messages as loss. Shutdown joins the reader before closing its socket.
  A dynamic incarnation never materialized must carry no FIB route
  and have no Babel UDP socket. This evidence is independent of daemon up claims;
  a tentative incarnation lasting over 90 seconds fails (30s UDP + 30s final
  validation + 10s deferred cleanup + 5s cleanup, with 15s sampling allowance).
  Such interfaces never satisfy required neighbors or committed counts.
- A saved Durable receiver may remain while its peer is offline or the Link is
  recovering. Exemption from the 90-second Attempt limit requires an actual saved
  agreement with the correct peer key and listening port. A receiver that has not committed must have no FIB route or Babel
  socket. A committed receiver retains admission and its neighbor fallback
  across control loss. A status claim alone cannot grant this exemption. Healthy Static Links
  must suppress duplicate automatic interfaces.
- All modeled reachable destinations have active routes using live WG peers.
  Following each best FIB path must reach its owner without cycles. Public/public
  and public/NAT pairs use required direct Links; optional NAT/NAT paths may
  traverse public nodes.
  Removed destinations must leave no learned unicast route behind. An exact
  protocol-202 neighbor fallback may remain on a previously materialized Link;
  it must never win selection for a reachable destination over a live path.
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
  it must exit before the stable window can complete. If exit empties the command
  line during inspection, the known Babel child also blocks stability until it
  disappears. Other extra processes fail with their observed identity recorded.
  NAT process liveness and fresh status
  are also checked, separately from the member's processes.

NAT fallback can traverse the member being removed, so survivor forwarding may
reconverge within the same finite phase deadline. Unlike the former all-public
full-mesh fixture, this harness does not assume every survivor path is unaffected.
Transient mismatches reset the stable window; a phase that never converges fails.
Control-session loss is detected after 30 seconds. Ordinary Dynamic Links
retain committed resources for the production recovery timeout (default 30
minutes from the last confirmation); Babel detects routing-neighbor loss separately. TCP negotiation closes on completion and does not own established
Link liveness. Health/recovery/failure timers retain their production values.
Only the promotion stability threshold is shortened by the explicit test setting
below, so membership churn can exercise Durable behavior. This runner does not
replace the separate real 30-minute controlled-failure E2E test.

| Option | Default | Meaning |
| --- | --- | --- |
| `--nodes` | 6 | Total reusable slots, at most 16 |
| `--min-nodes` | 3 | Require `3 <= min-nodes < nodes`; includes public slots |
| `--seed` | 1 | Repeatable topology, bootstrap, profile and add/delete sequence |
| `--rounds` | 0 | Membership rounds after exercises; zero is unlimited, startup is round 0 |
| `--underlay` | dual | Simultaneous IPv4/IPv6 NAT/public; `ipv4` and `ipv6` retain single-family runs |
| `--endpoint-matrix` | off | Finite four-public-node bilateral endpoint/fallback suite |
| `--endpoint-case` | all | Repeatable case selector; requires `--endpoint-matrix` |
| `--dynamic` | active | `active` or provisioned-graph-only `off` |
| `--nat-policy` | active | Initial NAT policy, `active` or `passive`; publics stay active |
| `--exercise` | none | Repeat option for distinct online exercises; each runs once before churn |
| `--durable-stable-seconds` | 30 | Test promotion stability threshold; does not change failure timeout |
| `--automatic-ports` | mixed | `system`, explicit `range` 40000–40999, or alternating nodes; Static ports remain explicitly fixed |
| `--quiet` | disabled | Keep progress in rotating artifact logs instead of stdout |
| `--capture` | disabled | Rotating UDP capture on this run's bridge; requires tcpdump |
| `--settle-timeout` | 180 | Budget for startup/mutation and each convergence phase |
| `--stable-seconds` | 10 | Required continuous successful audit interval |
| `--probe-pairs` | 16 | Rotating positive ping pairs per audit |
| `--rss-growth-mib` | 64 | Allowed per-process rolling median RSS growth |
| `--artifacts` | unique run directory | Must not already exist |

## Bounded online exercises

These exercises select the first NAT member and a public other than its bootstrap.
`durable` selects an actually promoted public/NAT pair, since soft admission does
not guarantee promotion of a particular pair. Its guaranteed cold-success fixture
requires `--nat-policy active`: a fresh NAT mapping needs an outbound initiator.
Ordinary passive membership churn remains supported with controlled recovery
and real routed fallback; a saved endpoint is not a guarantee of cold reachability.
They run after initial convergence and before the requested membership rounds.
They are explicit, deterministic fault cases, not yet randomized churn events.

| Exercise | Injection and independent acceptance |
| --- | --- |
| `policy` | SIGHUP off → passive → original policy. Retire automatic interfaces within 75s and verify disk cleanup. During 36s, off must not initiate; each peer may make at most one proposal to learn a missed policy update, with no repeated proposals. Passive must not initiate. Required public links recover; the target's independent Babel PID must survive reload. |
| `blackout` | Drop one direction of underlay UDP for one established non-bootstrap public/NAT pair for at least 40s. Require the selected Babel path to avoid the blocked Link and real bidirectional fallback before removing the fault, then recover direct connectivity. |
| `control-loss` | Block routed TCP/UDP VFP and remove the pair's automatic WG interfaces. Ordinary Dynamic must use fallback with actual control drops, then recover after unblocking. If already Durable, require direct recovery under the same agreement while routed control remains blocked. |
| `durable` | Wait for bilateral confirmed storage, destroy both namespaces/WG/NAT instances, preserve disk state, then start with Static and routed VFP blocked. Require fresh handshakes, direct routes and payload. Next reconfigure the member's bootstrap to that peer: Static must suppress automatic resources while retaining the agreement; restore the original bootstrap and verify Durable resumes. |
| `nat-reset` | Replace only the translator, clearing all mappings while member/Babel stay alive. The replacement must forward real traffic and all required direct paths recover. |
| `nat-rebind` | Clear mappings, change WAN address and allocation. Require current WG endpoints and payload recovery on required public/NAT Links; their changed fixed agreements must disappear, while a confirmed agreement fixing only the other side must remain. Disconnected optional NAT/NAT agreements still follow controlled recovery. |

Fault windows and recovery phases are separate. The recovery budget and production
retry timers are unchanged. Packet counters prove the injected drop matched real
traffic in the Dynamic fallback branch. Except for the two cold-restarted Durable
members, all
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
  and Durable/materialization verifier runtime sources.
- Rotating `events.jsonl` (about 16 MiB with backups), `samples.jsonl` (about
  2 MiB), per-slot daemon logs (about 2 MiB per slot).
- Atomically replaced `latest.json` with current topology and complete audit.
- `coverage.json`: cumulative verified samples by family/profile/policy/requirement/
  outcome, latest ordered node pairs, actual ping and local/remote proposal counts.
  Cross-family transit requirements are labeled `relay`; pairs also record their
  assigned discovery families. Verified events record expected components.
  Pair counts reset on birth or NAT replacement; sampled outcome does not invent
  an initiator when no proposal was observed. A finite run reports only the
  profiles actually verified, not all 36 merely because they exist in the catalog.
- Rotating `observations.jsonl` (about 12 MiB): intermediate kernel WG counters,
  routes, Babel sockets and actual ifindices, including partial reads before a
  later node fails. Each sample and daemon log carries host-monotonic elapsed
  time and round; events also identify the current exercise phase.
- Kernel observer statistics in snapshots, verified events and observer shutdown
  events: effective receive buffer, bytes/messages, link/route event counts,
  route additions/deletions by protocol, peak count in a one-second bucket and
  maximum drain interval. Counts live only as long as that node incarnation;
  route counters have at most 512 protocol/kind keys. Failure snapshots retain
  these diagnostics and the exception traceback even if node inspection never
  started. The route subscription observes IPv6; payload/FIB audits cover both
  payload families.
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

The wrapper normally uses an SSH PTY. `--detach` instead starts a separate VM
session with `nohup`/`setsid` and `--quiet`; SSH can close without stopping the run.
The unique asset directory contains `launcher.pid`, bounded-progress artifacts in
`run/`, a diagnostic `console.log`, and an `exit-code` file only after completion.
Read `run/manifest.json` for the actual runner PID and send SIGTERM to that PID
to request cleanup. The launcher PID is only the waiting shell. No service or
automatic restart is installed. SIGINT/SIGTERM/SIGHUP
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
# Root-only, 20,000-event bursts with both running and paused readers, interface recreation,
# premature Babel rejection, and idempotent IPv4/IPv6 Fabric route maintenance
# with repair of external deletion/mutation and stable parallel-Link fallback
# ownership (also part of hosted E2E CI):
go test -c -o /tmp/velvet-linux.test ./internal/linux
go test -c -o /tmp/velvet-runtime.test ./internal/runtime
sudo env PYTHONDONTWRITEBYTECODE=1 python3 tests/endless/check_materialization.py \
  --linux-test /tmp/velvet-linux.test --runtime-test /tmp/velvet-runtime.test
# Root-only, all 36 profiles with IPv4, IPv6, and one dual-stack translator:
sudo env PYTHONDONTWRITEBYTECODE=1 python3 tests/endless/check_nat.py
# Retained namespace references and SIGTERM during partial setup:
sudo env PYTHONDONTWRITEBYTECODE=1 python3 tests/endless/check_lifecycle.py \
  /absolute/path/to/velvetd /absolute/path/to/babel-rs \
  --nodes 4 --underlay ipv4 --artifacts /absolute/path/to/new-run
# Actual WG handoff with final VFP deliberately blocked: Babel must exclude
# the tentative Link throughout, then forwarding must retain the routed path.
sudo env PYTHONDONTWRITEBYTECODE=1 python3 tests/endless/check_commit.py \
  /absolute/path/to/velvetd /absolute/path/to/babel-rs \
  --nodes 4 --underlay ipv4 --artifacts /absolute/path/to/new-commit-run
# Cold partitions, a new NAT member, a real bootstrap bridge, then its removal:
# the ordinary oracle must pass every phase, including dual-stack Access.
sudo env PYTHONDONTWRITEBYTECODE=1 python3 tests/endless/check_partition.py \
  /absolute/path/to/velvetd /absolute/path/to/babel-rs \
  --nodes 10 --min-nodes 6 --underlay dual --wg-access \
  --artifacts /absolute/path/to/new-partition-run
```

The real UDP check independently varies destination IP, destination port and
local port, observes actual translated endpoints, tests unsolicited replies from
different external endpoints, and relies on kernel UDP delivery to validate
reply framing/checksums. The dual-stack cases use the same client ports in both
families through one translator process, checking that the mappings remain
independent. It supplies no Velvet protocol messages.

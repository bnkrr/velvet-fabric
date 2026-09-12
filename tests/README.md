# Dynamic Link validation

Dynamic Link acceptance follows the complete path: discover a reachable Node
UID over the existing Fabric, infer and measure locally, coordinate a bounded
UDP search, hand the same local endpoint to WireGuard, verify the peer over
link-bound VFP, commit the Link, and carry traffic over the resulting routes.
Failure must retain the existing routed path and release tentative resources.
A UDP probe or an algorithm simulation alone does not establish this result.

## Acceptance coverage

| Requirement | Formal coverage |
|---|---|
| Existing sparse Fabric becomes a direct mesh | `e2e/netns-dynamic.sh`: eight nodes, eight static and twenty dynamic Links; all 56 directed loopback pings, Domain traffic and routes using dynamic interfaces |
| Distributed admission and lifecycle | Runtime regressions cover UID validation before commit, simultaneous proposals, reservation reuse, versioned permission and independent retry/query budgets; netns covers passive mode, equivalent reload and retry after failure |
| Independent local inference and evidence progress | `internal/linkdiscovery/peer_matrix_test.go`: actual `RunPeer` on both sides, separate stores, candidate/round barriers and independent NAT ground truth |
| IPv4/IPv6 underlay and single public peer | Netns covers native IPv6, IPv6 stateful filtering, single-sided NAT44/NAT66 with both proposal origins, and dual NAT66; packet counters distinguish VFP probes from WG traffic |
| Active measurement and further candidate rounds | Real dual NAT with forced port translation; delayed control reports; unavailable static observer followed by another Fabric observer |
| Quiet encrypted public transport | Probe tests cover AEAD tampering, wrong keys, expiry, reordering, replay, no UDP replies even for valid probes, socket release and malformed-envelope fuzzing |
| Same-port UDP to WG handoff | Netns checks retained listen ports, real WG handshakes, committed Links and direct routes; runtime tests require current-operation peer `WG_READY` before enabling traffic |
| Recovery and configuration changes | Netns interrupts established link-bound VFP, checks recovery with the same WG interface, disables Dynamic Link, checks multi-hop fallback, then re-enables and rebuilds |
| Bounded failure and cleanup | Netns blocks probes, breaks routed control and randomizes translated ports; checks no false commit, released tentative WG/UDP resources and working multi-hop traffic |

## Ordinary Go tests

```sh
go test ./internal/inference ./internal/linkdiscovery
go test ./internal/linkdiscovery -run '^TestPeer.*Matrix$' -v
go test -race ./...
go vet ./...
go test ./internal/vfp/probe -run '^$' -fuzz '^FuzzPublicProbeEnvelope$' -fuzztime 5s
```

CI runs `go test -race ./...`. Simulation needs no privileges, Babel binary or
files under `.local/`. Public UDP transport tests need permission to open
ordinary IPv4 and IPv6 loopback UDP sockets. Silence, correct source observation,
replay rejection and port release are exercised for both families. Envelope
tests reject a mismatched source/destination family without consuming the
valid packet sequence. Fuzzing includes valid IPv4/IPv6 seeds with stable test
credentials across workers. Fuzzing is an additional bounded check, not part
of the default CI race command.

`internal/inference/survey.go` stores ordered `(local, remote, seen)` samples
and produces candidate batches and finite measurement plans. Infer performs no
network I/O and keeps no persistent inference stage. The daemon runs
`internal/linkdiscovery/peer.go`: each side owns its store and communicates via
candidate and round barriers. `peer_test.go` covers one-sided measurement
delay, peer-only evidence progress and bounded control loss. The older
centralized `Run` in `search.go` remains an additional algorithm harness.

The independent test NAT model implements EIM, ADM and APDM mapping, EIF, ADF
and APDF filtering, and preservation, fixed-offset, sequential and seeded
pseudorandom port allocation. Infer sees endpoint hints and actual observations;
it cannot inspect the model's classifications or allocation parameters.
Successful paths are checked against the model's private mapping/filter state.

The centralized harness exercises all 81 pairs of mapping/filter settings
with sequential allocation. The actual per-node `RunPeer` matrix repeats those
81 pairs for IPv4 and IPv6, each with existing primary-socket evidence and with
fresh stores plus passive public-IP hints as at daemon startup. Each of the
four runs currently connects 72 pairs and bounds the remaining nine (324 cases
in total); simultaneous APDM remains a possible fallback.

A separate per-node single-public matrix covers both address families, either
side public, all nine mapping/filter settings on the NAT side, and all four
allocation strategies (144 cases). Every case must connect, including random
allocation: a packet to the public peer can reveal the actual target-specific
mapping without predicting it. Every result must agree at both ends and respect
round and measurement budgets. These counts describe this model, not Internet
success rates; proposal origins are tested at the real VFP layer below.

Other algorithm tests cover randomized EIM reuse, baseline success, port
prediction, unavailable bootstrap observers, broad-search refusal, packet loss,
readiness delay, reordered/duplicate/stale reports, allocation interference,
IPv6, cancellation, resource failure and deadlines. Filtering is exercised by
overlapping outbound windows; it is not classified by Infer. Reports use an
out-of-band control path, with no UDP replies.

Runtime regressions in `dynamic_probe_regression_test.go` additionally check
session/operation association, overflow cancellation, handoff readiness and
late reports. In particular, valid reports arriving at 350ms during measurement
or 650ms during a candidate attempt must be accepted. The executor allows a
bounded report wait after its send window, without extending the parent task
deadline. This guards against prematurely discarding reports on a slower
multi-hop Fabric path.

## Babel compatibility

The managed integration and privileged tests pin `babel-rs` v0.6.0 at
`dbeede34abd8dff2422c39ab18a15949b0f38f11`. Local wrappers build a Git archive of
that commit, and hosted CI checks out the same published revision.
`manager_test.go` covers the structured `[[interfaces]]`/`match` configuration, static names and dynamic
interface patterns, explicit wired policy, top-level shutdown budget, origins
and export views. The real netns suites exercise Babel's own config validator,
control readiness/reload, interface attachment, route export and restart.

`shutdown_test.go` exercises an actual child process with an unavailable
control socket and four seconds of cleanup after SIGTERM. Fabric must allow
the configured five-second Babel shutdown budget plus one second of margin,
then reap the child. This guards against the former three-second SIGTERM wait
killing a correctly shutting-down daemon before it finishes cleanup.

## Real netns integration

`e2e/netns-udp-nat.py` runs real velvetd, pinned Babel, VFP, UDP and kernel WG
with a public static bootstrap observer and either directly addressed WAN
nodes, one Linux conntrack NAT, or two NATs. Public addresses here belong to an
isolated documentation-prefix WAN; no packets are sent to the Internet. The
original IPv4 cases and dual-stack lifecycle checks are:

| Case | Required result |
|---|---|
| `preserve` | Stateful filtering with preserved ports establishes a direct Link |
| `remap` | Forced source-port translation requires active evidence and another candidate round, then establishes a Link |
| `delayed-remap` | The remapping case succeeds with injected WAN/control-path delay |
| `blocked` | Public probes cannot pass; bounded failure releases resources and preserves multi-hop ping |
| `control-loss` | Routed VFP is reset during an accepted attempt; no commit, resources released, multi-hop ping works |
| `random` | Broad randomized SNAT allocation produces bounded fallback with cleanup and multi-hop ping |
| `observer-fallback` | Static observer cannot receive measurements; a second public Fabric observer supplies evidence needed to connect |
| `lifecycle`, `v6-lifecycle` | TCP failure preserves the Link; UDP expiry withdraws adjacency, then fresh UDP recovers the same WG interface. Disable cleans up through UDP timeout and restores multi-hop routing; re-enable rebuilds |

Twenty further cases cover address families and asymmetric reachability:

| Cases | Required result |
|---|---|
| `v{4,6}-single-{preserve,remap,random}-{public,nat}-init` (12) | A is directly addressed; B is behind NAT44/NAT66; the selected side is active and the other passive. Both proposal directions connect for all three allocation modes |
| `v6-native-{a,b}-init` (2) | Both peers use native IPv6 underlay; either proposal origin connects |
| `v6-filtered-{a,b}-init` (2) | Native IPv6 with stateful inbound UDP filtering on both peers still connects, proving outbound probing by the passive participant |
| `v6-dual-{preserve,remap}` (2) | Two NAT66 routers translate private ULA sources to WAN IPv6 addresses; preservation and forced source-port translation both connect |
| `v6-dual-{blocked,random}` (2) | Blocked probes or broad random allocation behind two NAT66 routers cause bounded fallback and resource cleanup |

IPv6 scenarios provide only IPv6 underlay addresses/endpoints. NAT66 uses actual
kernel `ip6` SNAT rules and stateful forwarding, not just a firewall or an
IPv6 overlay inside IPv4 WG. Single-public random allocation is expected to
connect; dual-random allocation is expected to fall back within budget.

Successful cases check actual WG handshake timestamps, committed Links, UDP
handoff logs, retained source address and port, final WG remote endpoint and
traffic routes through the new interface. nftables counters match the VFP
magic in peer-directed UDP payloads, proving both sides send and receive probes
rather than counting WireGuard data. Explicit-origin cases require a Proposal
from only the selected initiator and an Accept from the passive node. Every
case checks data-plane ping in both directions. Failed cases check the absence
of tentative WG interfaces and primary probe sockets. Router WAN input drops
unsolicited UDP so router-local ICMP handling does not create unintended conntrack reservations.

The `lifecycle` and `v6-lifecycle` cases assert that link-local TCP closes after
negotiation, then block TCP while checking the direct route and actual traffic
for longer than the UDP health deadline. They subsequently block only Link-local
VFP UDP, verify both protocol-202 adjacency withdrawals, and restore UDP while TCP is
still blocked: the same WG ifindex must recover. Finally, disabling one endpoint
must reclaim the remote Dynamic Link within 30 seconds of UDP failure detection
plus 30 seconds of recovery (75 seconds including scheduling margin), restore
multi-hop routing and carry real traffic. Babel convergence and same-WG recovery
are checked separately so routing convergence does not consume the recovery
window. IPv6 uses
real NAT66 underlay, not only an IPv6 overlay inside IPv4 WG.

Six additional cases cover continuous retry, using the production budgets:

| Cases | Required result |
|---|---|
| `v{4,6}-retry-blackout` | WG traffic is blocked until the first Attempt fails while Fabric fallback remains usable; after restoration a fresh Proposal and UDP handoff establish the real direct WG Link |
| `v{4,6}-policy-wakeup` | Active A receives a policy Decline from off B, does not keep proposing, and releases tentative resources; B reloads passive and its UDP update wakes A before the next slow query |
| `v{4,6}-policy-restart-query` | B restarts passive without its former peer cache; A recovers permission through its ordinary five-minute-plus-jitter query, without restarting A or accelerating its budget |

The successful retry verifier checks the current WG listen port and endpoint
against the last handoff, rather than assuming exactly one historical handoff.
The blackout case additionally requires multiple handoffs. Failed test logs and
configuration remain in the reported private runtime directory after network
resources are cleaned up.

The privileged CI suite and VM helper include all 35 cases:

```sh
tests/e2e/run-on-vm.sh all
tests/e2e/run-on-vm.sh nat
tests/e2e/run-on-vm.sh nat v4-single-random-public-init v6-single-random-nat-init v6-dual-remap
```

`all` also runs existing static-Link, Core CRUD, complex Core and eight-node
Babel/Dynamic Link suites. These ensure the integration preserves static
routing, ownership, multi-Plan forwarding, Babel convergence and reload.

## Validation limits

The 35-case netns suite uses specific Linux topologies, not every mapping/filter pair
in the simulator. Mapping expiry, hairpinning, nested NAT, arbitrary route
changes, background mapping contention and long-duration stability are not
established by this suite. IPv6 coverage uses one chosen underlay family per
task; it does not establish dual-stack family selection, NAT64 or NPTv6 behavior.
Lifecycle and retry cases test deliberate faults, admission transitions and
publisher restart. They do not prove recovery after arbitrary crashes or
long-term stability under every network change. Complete failed attempts now
return to the bounded retry scheduler rather than exhausting a configuration
generation.

The eight-node crash check separates supervisor recovery from routing readiness.
After the new Babel child is ready, it waits up to 240 seconds for both endpoints
to learn routes carrying the current origin sequences, with healthy route export.
This matches the pinned Babel restart suite: a random sequence behind surviving
feasibility history can take about three minutes to recover. Only then do the
unchanged Fabric forwarding and mesh checks run. An early successful ping over
stale pre-crash FIB state is insufficient to pass the routing prerequisite.
Failure to meet that prerequisite still fails the test as a Babel convergence
failure; it does not consume or relax a Dynamic-Link recovery budget.

Observer listeners are public in these scenarios, including a deliberately
unavailable bootstrap observer. General observer discovery behind NAT and its
own baseline candidate negotiation need additional scenarios. The survey's
three source ports, two offered observer endpoints and predictor's small
sequence neighborhood are initial heuristics. They are neither exhaustive NAT
classification nor a promise to connect every destination-dependent mapping.

Transport tests and fuzzing do not constitute a security audit or load test.
Public probe keys are supplied over the existing trusted Fabric control path;
this work does not add end-to-end identity protection against untrusted Fabric
members.

## Bounded coverage matrix and fault scenarios

The [directed suite](directed/README.md) adds finite profile-pair matrices,
observer failures, precise crash/handoff triggers, whole-Fabric partition/merge,
NAT expiry/contention/rebind, dual-stack and egress changes, real TCP/UDP and MTU
checks, and nested/shared kernel NAT. Each scenario states its direct/fallback
boundary and validates actual WG/FIB/packet evidence. It reuses the independent
host oracle without starting endless churn. Scenario existence is not a pass
record; per-case results and retained failures identify what actually passed.

```sh
tests/directed/run-on-vm.sh --group all
tests/directed/run-on-vm.sh --case partition --case data-mtu --family both
```

## Optional endless membership testing

The [endless netns harness](endless/README.md) mixes public nodes with per-node
NAT mapping/filter/allocation profiles. Every added member chooses one current
public as bootstrap; public nodes also churn, with at least one remaining.
An independent WG/FIB and real-packet verifier requires every eligible public/NAT
pair to connect directly; difficult NAT/NAT pairs may use verified routed fallback.
Coverage records actual profiles, directions and outcomes, with bounded intermediate
WG/FIB evidence. Optional online exercises cover policy changes, one-way underlay
loss, routed control loss, mapping reset and WAN endpoint changes. Deletion cleanup
and same-identity rejoin remain part of membership churn.
The NAT emulator itself has an independent 72-case real-UDP IPv4/IPv6 check.
`--rounds 0` is unlimited; a positive count uses the same path for bounded
validation. It is opt-in and separate from privileged E2E `all`.

```sh
tests/endless/run-on-vm.sh --nodes 16 --min-nodes 8 --rounds 0
tests/endless/run-on-vm.sh --nodes 4 --rounds 6 --underlay ipv6
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/endless -v
```

## Directed admission protocol regressions

`internal/vfp/message/policy_test.go` checks required/optional admission snapshots,
classified Decline, invalid revisions, extension handling and transport separation.
`internal/vfp/policy/socket_test.go` checks destination, source port, Fabric prefix
and ingress metadata, including underlay traffic claiming a Fabric address.
Runtime policy tests cover concurrent durable revision reservation, corruption,
restart, missing publisher cache, source/UUID conflicts, stale/duplicate snapshots,
late operations, independent budgets, reply coalescing, fairness and bounded caches.
The ordinary routed failure regressions retain the actual VFP session callbacks,
response timer and cleanup checks while requiring future retry eligibility.

## VM test configuration

Set `VELVET_VM_HOST` to your SSH destination and `VELVET_VM_REMOTE_ROOT`
to an absolute test asset directory. For Babel suites, set `VELVET_BABEL_REPO`
to a local Git checkout containing the pinned revision. Go and Cargo are
resolved through PATH; `VELVET_GO_BIN` and `VELVET_CARGO_BIN` can override
them. `VELVET_SSH_CONFIG` optionally selects an SSH configuration file.
Use a Linux build host with a matching VM architecture. Keep personal
defaults outside tracked files; configure caches/toolchains in the caller environment.

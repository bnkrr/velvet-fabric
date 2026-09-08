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
| Distributed admission and lifecycle | Runtime regressions cover UID validation before commit, simultaneous proposals, reservation reuse and one-shot failure; netns covers passive mode and equivalent reload |
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

The managed integration and privileged tests pin `babel-rs` v0.4.1 at
`b5e15d857d776c60179dcb6078a524b56b3ced94`. `manager_test.go` covers the
structured `[[interfaces]]`/`match` configuration, static names and dynamic
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
original IPv4 cases remain:

| Case | Required result |
|---|---|
| `preserve` | Stateful filtering with preserved ports establishes a direct Link |
| `remap` | Forced source-port translation requires active evidence and another candidate round, then establishes a Link |
| `delayed-remap` | The remapping case succeeds with injected WAN/control-path delay |
| `blocked` | Public probes cannot pass; bounded failure releases resources and preserves multi-hop ping |
| `control-loss` | Routed VFP is reset during an accepted attempt; no commit, resources released, multi-hop ping works |
| `random` | Broad randomized SNAT allocation produces bounded fallback with cleanup and multi-hop ping |
| `observer-fallback` | Static observer cannot receive measurements; a second public Fabric observer supplies evidence needed to connect |
| `lifecycle` | Established VFP recovers on the same WG interface; disable with a lost close notification still cleans up via TCP failure detection and restores multi-hop routing; re-enable rebuilds |

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

The lifecycle case deliberately drops outbound UDP to the peer during local
shutdown, so a TCP close notification cannot be relied on. Its remote cleanup
bound includes the existing TCP keepalive configuration (30s idle, three probes
10s apart), then the separate 30s Dynamic Link recovery budget. The test allows
105s including scheduling margin; it must not mistake the 30s recovery timer
for the entire failure-detection time.

The privileged CI suite and VM helper include all 28 cases:

```sh
tests/e2e/run-on-vm.sh all
tests/e2e/run-on-vm.sh nat
tests/e2e/run-on-vm.sh nat v4-single-random-public-init v6-single-random-nat-init v6-dual-remap
```

`all` also runs existing static-Link, Core CRUD, complex Core and eight-node
Babel/Dynamic Link suites. These ensure the integration preserves static
routing, ownership, multi-Plan forwarding, Babel convergence and reload.

## Validation limits

The netns cases are specific Linux topologies, not every mapping/filter pair
in the simulator. Mapping expiry, hairpinning, nested NAT, arbitrary route
changes, background mapping contention and long-duration stability are not
established by this suite. IPv6 coverage uses one chosen underlay family per
task; it does not establish dual-stack family selection, NAT64 or NPTv6 behavior.
The lifecycle case tests a broken VFP connection and deliberate disable/re-enable; it does not prove automatic
reconnection after arbitrary crashes. Fully failed attempts still follow the
specified one-shot-per-generation policy.

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

## VM test configuration

Set `VELVET_VM_HOST` to your SSH destination and `VELVET_VM_REMOTE_ROOT`
to an absolute test asset directory. For Babel suites, set `VELVET_BABEL_REPO`
to a local Git checkout containing the pinned revision. Go and Cargo are
resolved through PATH; `VELVET_GO_BIN` and `VELVET_CARGO_BIN` can override
them. `VELVET_SSH_CONFIG` optionally selects an SSH configuration file.
Use a Linux build host with a matching VM architecture. Keep personal
defaults outside tracked files; configure caches/toolchains in the caller environment.

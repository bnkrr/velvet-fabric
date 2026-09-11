# Bounded dynamic-link E2E

This suite exercises real velvetd, pinned Babel v0.4.1, kernel WireGuard and
VFP on isolated network namespaces. It is finite, separate from endless churn,
and makes no claims about load resistance or Internet success rates.

```sh
tests/directed/run-on-vm.sh --group all
tests/directed/run-on-vm.sh --group matrix --family ipv6
tests/directed/run-on-vm.sh --case partition --case crash-commit --family both
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/directed -v
```

The helper builds locally and transfers immutable assets to a unique VM
directory. Cases run serially, preserve successes and failures, and clean only
their own processes, namespaces, interfaces and UUID state. No endless service
or monitor is started. Each case retains binary hashes, topology, rotating
WG/FIB observations and packet capture, actual traffic results, fault counters,
and cleanup outcome. A failed case remains a failure even if another passes.

## Cases and assertions

| Cases | Required evidence |
|---|---|
| `matrix-L-R` (21 batches per family) | Every pair of all 36 mapping/filter/allocation profiles, including same-profile peers. Each NAT/NAT pair must actually reach success or a completed UDP failure. Every public/NAT pair and every EIM/EIM pair must connect directly. Other pairs may use an independently checked, functioning routed fallback. Every ordered reachable node pair carries real ping traffic. |
| `expiry-{mapping}-{allocation}` | With a 12-second fixture idle timer, block refresh in both directions for 16 seconds; the same translator process must expire all mappings itself. Restore traffic and require direct public/NAT recovery. No production timer is shortened. |
| `contention-{mapping}-{allocation}` | Independent UDP sockets consume real mappings starting before the NAT daemon boots and continuing throughout initial public/NAT Link establishment. Assert actual extra allocations and successful WG/FIB/data plane. |
| `rebind-{mapping}-{allocation}` | Replace the NAT WAN address and allocation policy without restarting velvetd/Babel. Assert actual WG endpoint migration and real TCP/UDP traffic. The three mappings × sequential/random allocation cover six profiles per fault, using APDF. |
| `observer-concurrency` | Reproduce many simultaneous observations in a 14-node topology. Record an actual FD/socket peak above the old per-Link-only estimate, then block new routed TCP opens. After 45 seconds, require zero owned public probe listeners and incoming routed TCP sessions, FDs back below the original per-Link budget, and unchanged WG/FIB/business checks. |
| `observer-nat` | Public observer control opens are blocked to leave room in the unchanged attempt budget for a NAT observer to be offered and tried at baseline. Unmapped listener failure must be bounded and preserve routed traffic; restoring public observers recovers required direct Links. |
| `observer-loss` | Interrupt a prepared observer's measurement path and require actual measured evidence from another observer. WG bootstrap remains intact. |
| `observer-conflict` | Destination-selected egresses give observers different real external IPs; the engine cannot assume those observations are identical. Verify measurements, both egress allocations and final forwarding. |
| `observer-ports` | After bootstrap initialization, occupy every remaining port in the public observers' ephemeral UDP pools; existing WG sockets account for the rest. Failed measurement resources must lead to bounded fallback; releasing the ports permits recovery. |
| `crash-observe`, `crash-handoff`, `crash-commit` | Kill velvetd after the selected observed stage, preserving namespace, NAT state, persistent UUID state and kernel interfaces. The commit case requires a real handshake while final VFP is blocked. Tentative interfaces cannot enter FIB/Babel. Restart and validate recovery with the production budgets. |
| `stale-candidate` | Change WAN address after probe preparation while candidate packets are gated, then require recovery with the new endpoint. |
| `partition` | Split the whole four-node Fabric into two components. Assert component-local routes/traffic, absence of cross-component traffic and actual dropped packets. Merge without restarting daemons, then require the complete topology and business traffic. |
| `dual-stack` | Both underlay families exist on each node. Fail the old family and change bootstrap hints; require actual static endpoint rotation onto the other family, then Babel and Dynamic Link recovery, with unchanged velvetd PIDs. |
| `dual-stack-failure` | Fail only the selected pair's initially used family while another family and Fabric remain available. Record actual alternate-family direct connection or bounded routed fallback; restore and require normal direct recovery. |
| `egress-switch` | Add a second physical egress, change the route/source address, and take the old egress down. Recover real traffic without restarting either daemon. |
| `data-mtu` | Bidirectional TCP/UDP receive checks, exact WG-MTU boundary and explicit rejection above it, then real business traffic with underlay MTU reduced to 1360. Uses kernel networking for fragmentation. |
| `nested-nat` | Add an actual inner conntrack SNAT in front of the outer NAT fixture. Both layers must translate real traffic, with required public adjacency and business traffic. |
| `shared-nat` | Two clients share one actual conntrack NAT/WAN address. First verify the available routed path, then enable explicit hairpin DNAT/SNAT using the shared WAN source (consistent with the configured candidate prefixes) and require direct client/client traffic with both translation counters hit. |

## Acceptance boundaries

The existing host-owned verifier retains its 180-second Fabric deadline,
10-second stable window, real route traversal, tentative-interface lifetime and
resource checks. The velvetd FD ceiling separately accounts for the bounded
128-observer pool (one TCP plus two UDP FDs per observer), in addition to per-Link
resources. The observer-concurrency regression checks that temporary sockets are
released after their 30-second leases; it also catches ordinary routed proposal
sessions left behind by simultaneous-proposal arbitration. Deliberate network
partitions change only the independently specified reachable components; they do not turn failed forwarding into success.
Crash recovery first requires current Babel origin sequences and a healthy
exporter within the existing 240-second routing prerequisite. Static address
family rotation separately gets 240 seconds because the production endpoint
staleness threshold is three minutes. Those dependencies do not consume or relax
the subsequent Fabric deadline.

The pair-specific family-loss case first requires direct adjacency withdrawal
within 40 seconds, then checks the same routing prerequisite: a higher-metric
Babel alternative can remain infeasible while old source history is retained.
It does not demand Fabric forwarding while Babel exports no route.

Business checks use modest rates (TCP 4 Mbit/s and UDP 1 Mbit/s for five seconds
in each direction), validate receiver bytes and zero UDP packet loss, and retain
both endpoints' JSON. They are connectivity/PMTU checks, not throughput benchmarks
or CPU/DoS testing. Public addresses are documentation prefixes on an isolated
WAN; no probes go to the Internet.

All 36 NAT profiles and their Cartesian pairs belong to the protocol-independent
real-UDP fixture. They are not an assertion about every real router's conntrack
behavior. Nested/shared cases add real kernel NAT, but do not cover arbitrary
layer counts, NAT64, NPTv6 or every hairpin policy. The raw UDP fixture does not
reassemble IP fragments; MTU fragmentation uses public kernel paths instead.

Both directions of a profile pair carry traffic. Matrix cases permit simultaneous
proposals; they do not force each side to be the sole initiator. Existing
single-public E2E cases continue to cover explicit initiator direction.
The four small observer fault cases isolate node 2 as the only active initiator, so another concurrent
peer attempt cannot supply the required measured-observer event. Observer failures
are not permission denials. A baseline-only observer behind an
unmapped NAT need not succeed. Family tests distinguish static bootstrap
rotation from automatic alternate-family selection inside a Dynamic Link
attempt; the latter is an observed capability boundary, not assumed support.

Scenario availability is not a pass record. Consult the run's `results.json`,
per-case failure/exception records and final cleanup events for actual results.

## VM test configuration

Set `VELVET_VM_HOST` to your SSH destination and `VELVET_VM_REMOTE_ROOT`
to an absolute test asset directory. For Babel suites, set `VELVET_BABEL_REPO`
to a local Git checkout containing the pinned revision. Go and Cargo are
resolved through PATH; `VELVET_GO_BIN` and `VELVET_CARGO_BIN` can override
them. `VELVET_SSH_CONFIG` optionally selects an SSH configuration file.
Use a Linux build host with a matching VM architecture. Keep personal
defaults outside tracked files; configure caches/toolchains in the caller environment.

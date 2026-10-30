# Changelog

## 0.7.1

- Scope business routes to their owning Domain. Access return prefixes use
  ordinary Babel routes and the shared Fabric return table; exits use
  source-specific routes. Each Domain table receives shared infrastructure and
  its own routes, with unreachable guards to prevent unintended fallthrough.
- Compile explicit Babel import and announcement policies independently of
  per-table export filters. Require Babel 0.8.1; `tests/babel-revision` records
  the exact compatible commit.
- Make kernel rule priorities independent of table IDs and mirror committed
  neighbor routes into Domain tables for source-based and fwmark Access.
- Replace historical NodeSpec routing and port fields with explicit
  `static_routes`, `source_table_id` and per-Link `listen_ports` settings. Update
  examples and the offline configuration editor to the same schema.
- Add dual-stack Domain isolation and policy reload regressions. Correct the
  endless Access verifier to accept only independently validated retained
  neighbor fallbacks while rejecting stale learned routes and dead best paths.

### Upgrade from 0.6.1

Install Babel 0.8.1 alongside Fabric 0.7.1. Older Babel versions cannot parse
the generated policy configuration. Back up NodeSpec and persistent state,
then regenerate the configuration or apply these changes before restarting:

| Previous field | Current configuration |
| --- | --- |
| `fabric.routes` | `fabric.static_routes`, restricted to configured infrastructure pools |
| `fabric.announcements` | Move each business announcement into its owning `domains.<name>.announcements` |
| `domains.<name>.table_id` | `domains.<name>.source_table_id` |
| `domains.<name>.routes` | `domains.<name>.static_routes` |
| Node or Peer `listen_port` / `port_range` | Explicit `listen_ports` on each Peer and under `dynamic_links` |

`listen_ports` accepts `0` for system allocation, one fixed port, or an inclusive
`[first, last]` range. Node-level defaults and derived static listen ports no
longer apply; set fixed ports explicitly where peers need predictable listeners.
Historical fields are rejected, even though NodeSpec still uses
`velvet.io/v1alpha2`. Validate with `velvetctl resolve --config node.json`.

Declare the same Domain source scope on participating transit nodes. Prefixes
contained within that scope are Access returns; other Domain destinations are
business exits. Move business static routes out of the Fabric infrastructure
section as well. Access provisioning, firewall policy and exit NAT remain host
responsibilities. See [Core routing](README.md#core-routing) for the complete
forwarding contract. Mixed-version rolling upgrades are not promised.

## 0.6.1

- Preserve committed WireGuard Links across Fabric stops, crashes and reloads,
  then adopt their validated kernel state on restart. Short VFP PONG loss marks
  control-session loss without tearing down forwarding. Ordinary Dynamic Links
  have a configurable recovery deadline, defaulting to 30 minutes.
- Run Babel independently from Fabric. Add systemd watchdog recovery and an
  independent timer that retires this instance's resources after prolonged
  local recovery failure. Pair this release with Babel 0.7.0 for bounded FIB
  recovery; `tests/babel-revision` records the exact tested source.
- Preserve monotonic time in runtime watchdog progress checks so system clock
  corrections do not change the stall deadline.
- Support configured VFP ports below 1024 in the packaged systemd service.
- Place automatic neighbor-loopback fallbacks below usable Babel routes and
  above Babel unreachable entries. Keep explicit static-route precedence and
  stabilize fallback ownership across parallel Links. Avoid rewriting unchanged
  kernel routes while continuing to repair external changes.
- Add Durable Link agreements, saved endpoint/port recovery and static takeover.
  Recover ordinary Dynamic Links when a peer rejoins after losing kernel state.
  Retry stale endpoint candidates and keep Discovery on the fixed VFP port so
  it cannot consume a saved WireGuard listen port.
- Restore scoped Access return routing. Add three-node examples, an offline
  NodeSpec editor and a local helper for building Fabric with pinned Babel.
- Extend regression coverage for systemd failures, dual-stack endpoint selection,
  Durable cold recovery, kernel ownership and repeated membership changes.
- Stage systemd acceptance tests in a root-owned runtime directory, retaining
  home isolation even when the checkout belongs to an unprivileged user.
- Build releases with Go 1.27.2 and update the Go networking dependencies to
  their current security revisions.

### Upgrade from 0.5.1

Install both Fabric binaries and the separate Babel 0.7.0 binary. Install all
four files in `packaging/systemd/`, run `systemctl daemon-reload`, then enable
`velvetd.service` and `velvet-recovery.timer`. Fabric manages the independent
`velvet-babel@<uuid>.service`; do not run another Babel service in the same network
namespace. See [operations](README.md#operations) for paths and overrides.

Upgrade both endpoints of every Link; older peers can still tear down Links on
control-session loss. Back up NodeSpec and persistent state before upgrading.
Preserve node identities, keys and `/var/lib/velvet` when replacing binaries so
saved Durable agreements remain available. The VFP wire format is still an
internal-development interface; mixed-version rolling upgrades are not promised.

Automatic loopback fallback priorities migrate during reconciliation. Fabric
validates loopback host-announcement metrics as multiples of 96; ordinary business
prefixes keep their existing metric range. User-configured WireGuard listen ports
must not equal `fabric.vfp_port`; allocation ranges can overlap it because the
allocator skips that port.

Normal Fabric shutdown now preserves committed Links and the independent Babel
process. Use configuration removal or explicit Babel disable to revoke managed
resources. Explicit static routes still outrank dynamic routes and do not gain
automatic next-hop failover. See [routing](README.md#dynamic-routing) for the
recovery window and shutdown behavior; forwarding is not guaranteed lossless.

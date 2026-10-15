# Changelog

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

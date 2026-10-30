# Install a Fabric binary release

Use Linux with kernel WireGuard and systemd. Select the archive matching the
host architecture, verify it against the release's `SHA256SUMS`, and extract it.
Run the following commands from the extracted archive directory:

```sh
sudo install -m 0755 velvetd velvetctl /usr/bin/
sudo install -d -m 0700 /etc/velvet
sudo install -m 0644 packaging/systemd/* /etc/systemd/system/
```

For dynamic routing, install Babel 0.8.0 separately and set `babel.executable`
in NodeSpec to its absolute installed path. Fabric's packaged unit manages an
independent `velvet-babel@<node-uuid>.service`; do not enable the standalone
`babel-rs.service` in the same network namespace.

Prepare a NodeSpec with your node identity, keys, peers and routing policy.
The [examples](../examples/README.md) and [offline editor](../web/README.md) can
help generate it. Replace all documentation addresses before use. Install the
node's configuration as a regular file readable only by its owner:

```sh
sudo install -m 0600 node.json /etc/velvet/node.json
sudo velvetctl resolve --config /etc/velvet/node.json
sudo systemctl daemon-reload
sudo systemctl enable --now velvetd.service velvet-recovery.timer
sudo velvetctl status --config /etc/velvet/node.json
```

Allow the configured WireGuard UDP ports through the host firewall and provide
working underlay routing. Fabric enables IP forwarding in its network namespace;
Access services, local delivery, forwarding firewall policy and exit NAT remain
host responsibilities. Dynamic Links improve an already connected Fabric and do
not replace its initial static connectivity.

The shipped units expect `/usr/bin/velvetd` and `/etc/velvet/node.json`. If changing
these paths, update the Fabric, Babel launcher and recovery unit commands together.
Use systemd overrides for custom settings. Keep the persistent `/var/lib/velvet`
directory across binary replacements; it contains identity and recovery state.

## Upgrade and restart

Back up the current configuration, persistent state and previous binaries.
Read the [migration notes](../CHANGELOG.md), install both Fabric binaries and
the compatible Babel binary, replace all four unit files, then run
`systemctl daemon-reload`.

Restart Fabric with `systemctl restart velvetd.service`. If the Babel binary
changed, also restart `velvet-babel@<node-uuid>.service`, using the UUID from
NodeSpec. Restarting Fabric alone intentionally leaves a running Babel process
alive. Check both services and actual traffic after the upgrade; a ready local
daemon does not mean every remote path has converged.

Upgrade all Link endpoints to obtain the new retention behavior. Keep a rollback
copy of the matching binaries and configuration/state snapshot; mixed-version
rolling upgrades and downgrades of saved state are not guaranteed compatible.

## Stops and prolonged failures

A normal Fabric stop preserves committed Links and does not stop Babel. Remove
peers or disable Babel through configuration and reload to revoke those resources.
The recovery timer retires this instance's kernel resources after a continuous
local recovery failure (30 minutes by default); normal stops do not start this
deadline. See [operations](../README.md#operations) for recovery overrides.

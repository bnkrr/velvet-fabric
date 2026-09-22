# Dynamic routing minimal: A–B–C

Use [a.json](a.json), [b.json](b.json), and [c.json](c.json) with the shared
[preparation and local delivery instructions](../README.md).

- A announces Access pool `10.100.20.0/24` in Fabric.
- C announces the default exit `0.0.0.0/0` in Domain `internet`.
- B configures the same Domain source set and forwards both directions.

There are no explicit `routes` fields. Managed Babel learns the outbound,
return and node-loopback paths. The A–B and B–C WireGuard peers remain
configured explicitly; this example does not enable Dynamic Links.

```sh
python3 examples/prepare.py dynamic_minimal .local/examples/dynamic_minimal \
  --babel /usr/local/bin/babel-rs
```

# Static minimal: A–B–C

Use [a.json](a.json), [b.json](b.json), and [c.json](c.json) with the shared
[preparation and local delivery instructions](../README.md).

- A announces Access pool `10.100.20.0/24` in Fabric and sends Domain default
  traffic to B.
- B sends Domain default traffic to C and Fabric return traffic to A.
- C announces the Domain default exit and sends Fabric return traffic to B.
- A and C have explicit routes to each other's node loopback. Direct-neighbor
  loopbacks are installed from established Links.

Babel is absent. `fabric.static_routes` carries infrastructure paths;
`domains.internet.static_routes` carries outbound and Access return paths. All three nodes must run
`velvetd`; Access and upstream delivery are configured separately.

```sh
python3 examples/prepare.py static_minimal .local/examples/static_minimal
```

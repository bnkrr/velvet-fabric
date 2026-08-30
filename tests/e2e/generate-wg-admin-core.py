#!/usr/bin/env python3
"""Generate Velvet NodeSpecs for the wg-admin complex Core topology."""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path
import sys


RUNTIME = Path(sys.argv[1])

NODES = {
    "ea": {"index": 1, "underlay": "192.0.2.11"},
    "eb": {"index": 2, "underlay": "192.0.2.12"},
    "r1": {"index": 3, "underlay": "192.0.2.21"},
    "r2": {"index": 4, "underlay": "192.0.2.22"},
    "r3": {"index": 5, "underlay": "192.0.2.23"},
    "xa": {"index": 6, "underlay": "192.0.2.31"},
    "xb": {"index": 7, "underlay": "192.0.2.32"},
    "xc": {"index": 8, "underlay": "192.0.2.33"},
}

# entry-a/entry-b, relay-1/2/3, and exit-a/b/c from wg-admin's
# test_complex_netns_real_deployment_browser_e2e.
EDGES = [
    ("ea", "r1"),
    ("r1", "xa"),
    ("ea", "r2"),
    ("r2", "xb"),
    ("eb", "r2"),
    ("eb", "r3"),
    ("r3", "xc"),
    ("r2", "r1"),
]

PLANS = {
    "plan-a": {
        "table": 20030,
        "members": {"ea", "eb", "r1", "r2", "xa", "xb"},
        "sources": {
            "10.100.30.0/24": "ea",
            "10.100.32.0/24": "eb",
        },
        "targets": {
            "10.60.1.0/24": "xa",
            "10.60.2.0/24": "xb",
            "10.100.201.0/24": "xa",
            "10.100.202.0/24": "xb",
        },
    },
    "plan-b": {
        "table": 20031,
        "members": {"eb", "r1", "r2", "r3", "xa", "xb", "xc"},
        "sources": {"10.100.31.0/24": "eb"},
        "targets": {
            "10.60.2.0/24": "xb",
            "10.60.3.0/24": "xc",
            "10.61.1.0/24": "xa",
        },
    },
}


def adjacency(members: set[str] | None = None) -> dict[str, list[str]]:
    selected = set(NODES) if members is None else members
    result = {node: [] for node in selected}
    for left, right in EDGES:
        if left in selected and right in selected:
            result[left].append(right)
            result[right].append(left)
    for neighbors in result.values():
        neighbors.sort()
    return result


def next_hop(source: str, target: str, members: set[str] | None = None) -> str:
    graph = adjacency(members)
    queue = deque([(source, [])])
    visited: set[str] = set()
    while queue:
        current, path = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        if current == target:
            if not path:
                raise ValueError(f"{source} is already the target")
            return path[0]
        for neighbor in graph[current]:
            queue.append((neighbor, [*path, neighbor]))
    raise ValueError(f"no path from {source} to {target}")


def group_route(groups: dict[str, list[str]], peer: str, prefix: str) -> None:
    groups.setdefault(peer, []).append(prefix)


ports: dict[tuple[str, str], int] = {}
for edge_index, (left, right) in enumerate(EDGES):
    ports[(left, right)] = 52000 + edge_index * 2
    ports[(right, left)] = 52001 + edge_index * 2

fabric_psk = (RUNTIME / "fabric.psk").read_text(encoding="ascii").strip()
private_keys = {
    node: (RUNTIME / f"{node}.key").read_text(encoding="ascii").strip()
    for node in NODES
}
public_keys = {
    node: (RUNTIME / f"{node}.pub").read_text(encoding="ascii").strip()
    for node in NODES
}
full_graph = adjacency()

for node, metadata in NODES.items():
    peers = []
    for peer in full_graph[node]:
        peers.append(
            {
                "name": peer,
                "public_key": public_keys[peer],
                "endpoints": [f"{NODES[peer]['underlay']}:{ports[(peer, node)]}"],
                "listen_port": ports[(node, peer)],
                "interface_name": f"vl-{node}-{peer}",
            }
        )

    fabric_routes: dict[str, list[str]] = {}
    for target, target_metadata in NODES.items():
        if target == node or target in full_graph[node]:
            continue
        group_route(
            fabric_routes,
            next_hop(node, target),
            f"fd78:abcd::{target_metadata['index']}/128",
        )

    domains = {}
    for plan_name, plan in PLANS.items():
        members = plan["members"]
        if node not in members:
            continue
        routes: dict[str, list[str]] = {}
        announcements: list[str] = []
        resources = {**plan["sources"], **plan["targets"]}
        for prefix, owner in resources.items():
            if owner == node:
                announcements.append(prefix)
            else:
                group_route(routes, next_hop(node, owner, members), prefix)
        domains[plan_name] = {
            "table_id": plan["table"],
            "source_prefixes": list(plan["sources"]),
            "routes": routes,
            "announcements": announcements,
        }

    value = {
        "api_version": "velvet.io/v1alpha1",
        "kind": "NodeSpec",
        "fabric": {
            "psk": fabric_psk,
            "loopback_prefix_v6": "fd78:abcd::/48",
            "routing_table_id": 20000,
            "routes": fabric_routes,
        },
        "node": {
            "uid": {
                "name": node,
                "uuid": f"10000000-0000-4000-8000-{metadata['index']:012d}",
            },
            "private_key": private_keys[node],
            "loopback_address_v6": f"fd78:abcd::{metadata['index']}",
        },
        "peers": peers,
        "domains": domains,
    }
    (RUNTIME / f"{node}.json").write_text(
        json.dumps(value, indent=2) + "\n", encoding="utf-8"
    )

#!/usr/bin/env python3
"""Generate latest NodeSpecs with static Links and no static multi-hop routes."""

from __future__ import annotations

import json
from pathlib import Path
import sys


RUNTIME = Path(sys.argv[1])
BABEL_RS = sys.argv[2]
DYNAMIC_LINKS = len(sys.argv) > 3 and sys.argv[3] == "dynamic-links"

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

DOMAINS = {
    "plan-a": {
        "source_table_id": 20030,
        # Ordering is semantic: the first prefix per family is Babel's canonical S.
        "source_prefixes": ["10.100.30.0/24", "10.100.32.0/24",
                            "fd30:100:30::/64", "fd30:100:32::/64"],
        "origins": {
            "ea": ["10.100.30.0/24", "fd30:100:30::/64"],
            "eb": ["10.100.32.0/24", "fd30:100:32::/64"],
            "xa": ["10.60.1.0/24", "10.100.201.0/24", "fd30:60:1::/64"],
            "xb": ["10.60.2.0/24", "10.100.202.0/24"],
        },
    },
    "plan-b": {
        "source_table_id": 20031,
        "source_prefixes": ["10.100.31.0/24"],
        "origins": {
            "eb": ["10.100.31.0/24"],
            "xa": ["10.61.1.0/24"],
            "xb": ["10.60.2.0/24"],
            "xc": ["10.60.3.0/24"],
        },
    },
}


def adjacency() -> dict[str, list[str]]:
    result = {node: [] for node in NODES}
    for left, right in EDGES:
        result[left].append(right)
        result[right].append(left)
    for peers in result.values():
        peers.sort()
    return result


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

graph = adjacency()
for node, metadata in NODES.items():
    peers = [
        {
            "name": peer,
            "public_key": public_keys[peer],
            "endpoints": (
                [
                    f"192.0.2.250:{ports[(peer, node)]}",
                    f"{NODES[peer]['underlay']}:{ports[(peer, node)]}",
                ]
                if {node, peer} == {"r3", "xc"}
                else [f"{NODES[peer]['underlay']}:{ports[(peer, node)]}"]
            ),
            "listen_ports": ports[(node, peer)],
            "interface_name": f"vl-{node}-{peer}",
        }
        for peer in graph[node]
    ]
    members = {"plan-a": {"ea","eb","r1","r2","xa","xb"}, "plan-b": {"eb","r1","r2","r3","xa","xb","xc"}}
    domains = {
        name: {
            "source_table_id": domain["source_table_id"],
            "source_prefixes": domain["source_prefixes"],
            **(
                {"announcements": [prefix for prefix in domain["origins"][node]
                                   ]}
                if node in domain["origins"]
                else {}
            ),
        }
        for name, domain in DOMAINS.items() if node in members[name]
    }
    value = {
        "api_version": "velvet.io/v1alpha2",
        "kind": "NodeSpec",
        "fabric": {
            "psk": fabric_psk,
            "loopback_prefix_v6": "fd78:abcd::/48",
            "routing_table_id": 20000,
        },
        "node": {
            "uid": {
                "name": node,
                "uuid": f"20000000-0000-4000-8000-{metadata['index']:012d}",
            },
            "private_key": private_keys[node],
            "loopback_address_v6": f"fd78:abcd::{metadata['index']}",
        },
        "peers": peers,
        "babel": {"enabled": True, "executable": BABEL_RS},
        "domains": domains,
    }
    if DYNAMIC_LINKS:
        value["dynamic_links"] = {
            # Keep one node passive: all seven active peers must still create
            # their half of its Links, while active/active pairs exercise the
            # simultaneous-Proposal arbitration path.
            "mode": "passive" if node == "xc" else "active",
            "allow_candidate_prefixes": ["192.0.2.0/24"],
        }
    (RUNTIME / f"{node}.json").write_text(
        json.dumps(value, indent=2) + "\n", encoding="utf-8"
    )

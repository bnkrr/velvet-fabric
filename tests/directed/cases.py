"""Finite full-stack scenarios. Requirements come from topology, not logs."""
from itertools import combinations_with_replacement, product

PROFILES = list(product(('eim', 'adm', 'apdm'), ('eif', 'adf', 'apdf'),
                        ('preserve', 'offset', 'sequential', 'random')))


def catalog():
    cases = {}
    # Six profiles per group, two groups per topology. Duplicate groups cover
    # same-profile peers too. Every unordered pair of all 36 profiles appears;
    # both directions carry traffic. This does not force a proposal origin.
    for left, right in combinations_with_replacement(range(6), 2):
        profiles = PROFILES[left * 6:(left + 1) * 6] + PROFILES[right * 6:(right + 1) * 6]
        cases[f'matrix-{left}-{right}'] = dict(kind='matrix', profiles=profiles)
    cases['observer-concurrency'] = dict(kind='observer-concurrency', profiles=PROFILES[6:12] + PROFILES[18:24])
    for name in ('partition', 'dual-stack', 'dual-stack-failure', 'egress-switch', 'data-mtu',
                 'nested-nat', 'shared-nat', 'observer-nat', 'observer-loss',
                 'observer-conflict', 'observer-ports',
                 'crash-observe', 'crash-handoff', 'crash-commit', 'stale-candidate'):
        cases[name] = dict(kind=name)
    for mapping, allocation in product(('eim', 'adm', 'apdm'), ('sequential', 'random')):
        for fault in ('expiry', 'contention', 'rebind'):
            cases[f'{fault}-{mapping}-{allocation}'] = dict(kind=fault,
                profiles=[(mapping, 'apdf', allocation), ('eim', 'eif', 'preserve')])
    return cases


def pair_requirements(profiles):
    # EIM on both sides can reuse actual primary-socket observations for any
    # allocation/filter combination; public observers are reachable here.
    # Other dual-NAT cases must complete an attempt and carry traffic via
    # either direct WG or the independently verified Fabric fallback.
    return {(a + 2, b + 2) for a, pa in enumerate(profiles) for b, pb in enumerate(profiles)
            if a != b and pa[0] == pb[0] == 'eim'}
